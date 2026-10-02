using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Kdf108.Domain.Sp80056A;
using Kdf108.Simple;
using Microsoft.Extensions.Logging;
using Spectre.Console;
using Spectre.Console.Cli;
using Kdf108.Examples.Infrastructure;

namespace Kdf108.Examples.Commands;

/// <summary>
/// Performance benchmark command that measures KDF operations per second
/// for different algorithms and key sizes.
/// </summary>
public class BenchmarkCommand : AsyncCommand<BenchmarkCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Number of iterations per test")]
        [CommandOption("-i|--iterations")]
        [DefaultValue(10000)]
        public int Iterations { get; init; } = 10000;

        [Description("Enable verbose output with detailed timing")]
        [CommandOption("-v|--verbose")]
        [DefaultValue(false)]
        public bool Verbose { get; init; }

        [Description("Include ECDH key agreement benchmarks")]
        [CommandOption("-e|--include-ecdh")]
        [DefaultValue(false)]
        public bool IncludeEcdh { get; init; }
    }

    public override async Task<int> ExecuteAsync([NotNull] CommandContext context, [NotNull] Settings settings)
    {
        var loggerFactory = LoggingSetup.CreateLoggerFactory(settings.Verbose);
        var logger = loggerFactory.CreateLogger<BenchmarkCommand>();

        AnsiConsole.Write(new Rule("[cyan]KDF Performance Benchmark[/]").RuleStyle("grey"));
        AnsiConsole.MarkupLine($"[dim]Running {settings.Iterations:N0} iterations per test to measure performance[/]");
        AnsiConsole.WriteLine();

        try
        {
            await RunKdfBenchmarks(settings, logger);
            
            if (settings.IncludeEcdh)
            {
                await RunEcdhBenchmarks(settings, loggerFactory, logger);
            }

            return 0;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during benchmark execution");
            AnsiConsole.Write(new Panel($"[red]Error:[/] {ex.Message}")
                .Header("[red]Failed[/]")
                .BorderColor(Color.Red));
            return 1;
        }
    }

    private async Task RunKdfBenchmarks(Settings settings, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[green]SP 800-108 KDF Benchmarks[/]").RuleStyle("green"));
        AnsiConsole.WriteLine();

        var masterKey = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(masterKey);
        }
        var context = System.Text.Encoding.UTF8.GetBytes("benchmark-context");

        var benchmarks = new[]
        {
            new { Purpose = "16-byte-key", OutputLength = 16, Description = "AES-128 key" },
            new { Purpose = "32-byte-key", OutputLength = 32, Description = "AES-256 key" },
            new { Purpose = "64-byte-key", OutputLength = 64, Description = "Large key material" }
        };

        var resultsTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[blue]Test Case[/]")
            .AddColumn("[green]Operations/sec[/]")
            .AddColumn("[yellow]Avg Time[/]")
            .AddColumn("[grey]Total Time[/]");

        foreach (var benchmark in benchmarks)
        {
            AnsiConsole.MarkupLine($"[dim]Benchmarking {benchmark.Description}...[/]");
            
            var stopwatch = Stopwatch.StartNew();
            
            await AnsiConsole.Progress()
                .AutoClear(false)
                .HideCompleted(true)
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new RemainingTimeColumn(),
                })
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask($"[cyan]{benchmark.Description}[/]", maxValue: settings.Iterations);
                    
                    for (int i = 0; i < settings.Iterations; i++)
                    {
                        SecureKeyDerivation.DeriveKey(
                            masterKey,
                            benchmark.Purpose,
                            benchmark.OutputLength,
                            context,
                            logger);
                        
                        task.Increment(1);
                        
                        // Yield control occasionally to keep UI responsive
                        if (i % 1000 == 0)
                        {
                            await Task.Delay(1);
                        }
                    }
                });
            
            stopwatch.Stop();
            
            var operationsPerSecond = settings.Iterations / stopwatch.Elapsed.TotalSeconds;
            var avgTimePerOp = stopwatch.Elapsed.TotalMilliseconds / settings.Iterations;
            
            resultsTable.AddRow(
                benchmark.Description,
                $"{operationsPerSecond:N0}",
                $"{avgTimePerOp:F3} ms",
                $"{stopwatch.Elapsed.TotalMilliseconds:F0} ms");
            
            await Task.Delay(100);
        }

        AnsiConsole.Write(resultsTable);
        AnsiConsole.WriteLine();
    }

    private async Task RunEcdhBenchmarks(Settings settings, ILoggerFactory loggerFactory, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[yellow]ECDH Key Agreement Benchmarks[/]").RuleStyle("yellow"));
        AnsiConsole.WriteLine();

        var curves = new[] { "P-256", "P-384", "P-521" };
        var ecdhIterations = Math.Min(settings.Iterations / 10, 1000); // ECDH is slower

        var ecdhTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[blue]Curve[/]")
            .AddColumn("[green]Key Gen/sec[/]")
            .AddColumn("[yellow]Agreement/sec[/]")
            .AddColumn("[grey]Total Time[/]");

        foreach (var curve in curves)
        {
            AnsiConsole.MarkupLine($"[dim]Benchmarking ECDH on {curve}...[/]");
            
            // Benchmark key generation
            var keyGenStopwatch = Stopwatch.StartNew();
            var keyPairs = new EcKeyPair[ecdhIterations];
            
            for (int i = 0; i < ecdhIterations; i++)
            {
                keyPairs[i] = EcKeyPair.GenerateRandom(curve, loggerFactory.CreateLogger<EcKeyPair>());
            }
            
            keyGenStopwatch.Stop();
            
            // Benchmark key agreement
            var agreementStopwatch = Stopwatch.StartNew();
            
            for (int i = 0; i < ecdhIterations - 1; i++)
            {
                EcdhKeyAgreement.ComputeSharedSecret(
                    keyPairs[i].PrivateKey,
                    keyPairs[i + 1].PublicKey,
                    logger);
            }
            
            agreementStopwatch.Stop();
            
            var keyGenPerSecond = ecdhIterations / keyGenStopwatch.Elapsed.TotalSeconds;
            var agreementPerSecond = (ecdhIterations - 1) / agreementStopwatch.Elapsed.TotalSeconds;
            var totalTime = keyGenStopwatch.Elapsed.TotalMilliseconds + agreementStopwatch.Elapsed.TotalMilliseconds;
            
            ecdhTable.AddRow(
                curve,
                $"{keyGenPerSecond:N0}",
                $"{agreementPerSecond:N0}",
                $"{totalTime:F0} ms");
            
            await Task.Delay(100);
        }

        AnsiConsole.Write(ecdhTable);
        AnsiConsole.WriteLine();
        
        if (settings.Verbose)
        {
            AnsiConsole.Write(new Rule("[dim]Performance Notes[/]").RuleStyle("grey"));
            AnsiConsole.MarkupLine("[dim]• KDF operations are CPU-bound and scale with output length[/]");
            AnsiConsole.MarkupLine("[dim]• ECDH performance varies significantly by curve (P-256 fastest, P-521 slowest)[/]");
            AnsiConsole.MarkupLine("[dim]• Key generation includes secure random number generation overhead[/]");
            AnsiConsole.MarkupLine("[dim]• Results may vary based on CPU, memory, and system load[/]");
        }
    }
}
