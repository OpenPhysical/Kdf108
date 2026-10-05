using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Kdf108.Simple;
using Spectre.Console;
using Spectre.Console.Cli;
using Microsoft.Extensions.Logging;
using Kdf108.Examples.Infrastructure;

namespace Kdf108.Examples.Commands;

public class DeriveKeyCommand : AsyncCommand<DeriveKeyCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Master key in hex format")]
        [CommandOption("-k|--master-key")]
        public string MasterKey { get; init; } = "404142434445464748494A4B4C4D4E4F";

        [Description("Purpose/label for the derived key")]
        [CommandOption("-p|--purpose")]
        public string Purpose { get; init; } = "encryption";

        [Description("Output length in bytes")]
        [CommandOption("-l|--output-length")]
        [DefaultValue(32)]
        public int OutputLength { get; init; } = 32;

        [Description("Context data in hex format (optional)")]
        [CommandOption("-c|--context")]
        public string? Context { get; init; }

        [Description("Enable verbose logging")]
        [CommandOption("-v|--verbose")]
        [DefaultValue(false)]
        public bool Verbose { get; init; }
    }

    public override async Task<int> ExecuteAsync([NotNull] CommandContext context, [NotNull] Settings settings, CancellationToken cancellationToken)
    {
        // Setup logging
        var loggerFactory = LoggingSetup.CreateLoggerFactory(settings.Verbose);
        var logger = loggerFactory.CreateLogger<DeriveKeyCommand>();

        // Display header
        AnsiConsole.Write(new Rule("[cyan]SP 800-108 Key Derivation[/]").RuleStyle("grey"));
        AnsiConsole.WriteLine();

        try
        {
            // Parse inputs
            var masterKey = Convert.FromHexString(settings.MasterKey);
            var contextData = settings.Context != null ? Convert.FromHexString(settings.Context) : null;

            // Show inputs
            var inputTable = new Table()
                .Border(TableBorder.Rounded)
                .AddColumn("[blue]Parameter[/]")
                .AddColumn("[green]Value[/]")
                .AddRow("Master Key", $"{settings.MasterKey} ({masterKey.Length} bytes)")
                .AddRow("Purpose", settings.Purpose)
                .AddRow("Output Length", $"{settings.OutputLength} bytes")
                .AddRow("Context", settings.Context ?? "[grey]None[/]");

            AnsiConsole.Write(inputTable);
            AnsiConsole.WriteLine();

            // Perform key derivation with progress
            byte[] derivedKey = Array.Empty<byte>();

            await AnsiConsole.Progress()
                .AutoClear(false)
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new SpinnerColumn(),
                })
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[cyan]Deriving key...[/]");
                    
                    task.Increment(20);
                    await Task.Delay(100); // Visual effect
                    
                    AnsiConsole.MarkupLine("   [grey]→ Initializing HMAC-SHA256 PRF[/]");
                    task.Increment(20);
                    await Task.Delay(100);
                    
                    AnsiConsole.MarkupLine("   [grey]→ Applying Counter Mode KDF[/]");
                    task.Increment(20);
                    await Task.Delay(100);
                    
                    // Actual derivation
                    derivedKey = SecureKeyDerivation.DeriveKey(
                        masterKey,
                        settings.Purpose,
                        settings.OutputLength,
                        contextData,
                        logger);
                    
                    task.Increment(40);
                    AnsiConsole.MarkupLine("   [grey]→ Key derivation complete[/]");
                });

            AnsiConsole.WriteLine();

            // Display result
            var resultPanel = new Panel(
                new Markup($"[green]Derived Key:[/]\n[yellow]{Convert.ToHexString(derivedKey)}[/]"))
                .Header("[green]✓ Success[/]")
                .BorderColor(Color.Green)
                .Expand();

            AnsiConsole.Write(resultPanel);

            // Show additional details if verbose
            if (settings.Verbose)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.Write(new Rule("[dim]Technical Details[/]").RuleStyle("grey"));
                
                var detailsTable = new Table()
                    .Border(TableBorder.None)
                    .HideHeaders()
                    .AddColumn("")
                    .AddColumn("")
                    .AddRow("[grey]Algorithm:[/]", "HMAC-SHA256")
                    .AddRow("[grey]Mode:[/]", "Counter (SP 800-108)")
                    .AddRow("[grey]Counter Size:[/]", "32 bits")
                    .AddRow("[grey]Counter Location:[/]", "Before Fixed Input");
                
                AnsiConsole.Write(detailsTable);
            }

            return 0;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during key derivation");
            
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Panel($"[red]Error:[/] {ex.Message}")
                .Header("[red]✗ Failed[/]")
                .BorderColor(Color.Red));
            
            return 1;
        }
    }
}
