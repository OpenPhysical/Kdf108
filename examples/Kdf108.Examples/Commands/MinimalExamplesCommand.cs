using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Kdf108.Simple;
using Microsoft.Extensions.Logging;
using Spectre.Console;
using Spectre.Console.Cli;
using Kdf108.Examples.Infrastructure;

namespace Kdf108.Examples.Commands;

/// <summary>
/// Minimal working examples that demonstrate the core functionality.
/// These examples focus on simplicity and guaranteed compilation.
/// </summary>
public class MinimalExamplesCommand : AsyncCommand<MinimalExamplesCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Enable verbose logging")]
        [CommandOption("-v|--verbose")]
        [DefaultValue(false)]
        public bool Verbose { get; init; }
    }

    public override async Task<int> ExecuteAsync([NotNull] CommandContext context, [NotNull] Settings settings, CancellationToken cancellationToken)
    {
        var loggerFactory = LoggingSetup.CreateLoggerFactory(settings.Verbose);
        var logger = loggerFactory.CreateLogger<MinimalExamplesCommand>();

        AnsiConsole.Write(new Rule("[cyan]Minimal KDF-108 Examples[/]").RuleStyle("grey"));
        AnsiConsole.MarkupLine("[dim]These examples demonstrate the core functionality with minimal complexity.[/]");
        AnsiConsole.WriteLine();

        try
        {
            await BasicKdfExample(logger);
            await MultipleKeyExample(logger);
            await ContextExample(logger);
            await SimpleApiExample(logger);

            return 0;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error running examples");
            AnsiConsole.Write(new Panel($"[red]Error:[/] {ex.Message}")
                .Header("[red]✗ Failed[/]")
                .BorderColor(Color.Red));
            return 1;
        }
    }

    /// <summary>
    /// Basic key derivation example using the simple API.
    /// </summary>
    private async Task BasicKdfExample(ILogger logger)
    {
        AnsiConsole.Write(new Rule("[green]Example 1: Basic Key Derivation[/]").RuleStyle("green"));
        AnsiConsole.WriteLine();

        // Master key (32 bytes for HMAC-SHA256)
        var masterKeyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        var masterKey = Convert.FromHexString(masterKeyHex);

        AnsiConsole.MarkupLine($"[bold]Master Key:[/] {masterKeyHex}");
        AnsiConsole.WriteLine();

        // Derive a 32-byte encryption key
        var encryptionKey = SecureKeyDerivation.DeriveKey(
            masterKey, 
            "encryption", 
            32, 
            null, 
            logger);

        AnsiConsole.MarkupLine($"[bold]Purpose:[/] encryption");
        AnsiConsole.MarkupLine($"[bold]Output Length:[/] 32 bytes");
        AnsiConsole.MarkupLine($"[bold]Derived Key:[/] {Convert.ToHexString(encryptionKey)}");
        AnsiConsole.WriteLine();

        await Task.Delay(500);
    }

    /// <summary>
    /// Example showing multiple keys derived from the same master key.
    /// </summary>
    private async Task MultipleKeyExample(ILogger logger)
    {
        AnsiConsole.Write(new Rule("[yellow]Example 2: Multiple Keys from One Master[/]").RuleStyle("yellow"));
        AnsiConsole.WriteLine();

        var masterKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");

        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[blue]Purpose[/]")
            .AddColumn("[green]Key (hex)[/]")
            .AddColumn("[grey]Length[/]");

        // Derive different keys for different purposes
        var purposes = new[] { "encryption", "authentication", "key-wrapping", "session-id" };
        var lengths = new[] { 32, 32, 16, 16 };

        for (int i = 0; i < purposes.Length; i++)
        {
            var key = SecureKeyDerivation.DeriveKey(masterKey, purposes[i], lengths[i], null, logger);
            table.AddRow(purposes[i], Convert.ToHexString(key), $"{lengths[i]} bytes");
            await Task.Delay(100); // Visual effect
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();

        await Task.Delay(500);
    }

    /// <summary>
    /// Example showing the use of context data for additional key separation.
    /// </summary>
    private async Task ContextExample(ILogger logger)
    {
        AnsiConsole.Write(new Rule("[magenta]Example 3: Key Derivation with Context[/]").RuleStyle("magenta"));
        AnsiConsole.WriteLine();

        var masterKey = Convert.FromHexString("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210");

        // Same purpose, different contexts
        var purpose = "user-key";
        var user1Context = System.Text.Encoding.UTF8.GetBytes("user-alice");
        var user2Context = System.Text.Encoding.UTF8.GetBytes("user-bob");

        var aliceKey = SecureKeyDerivation.DeriveKey(masterKey, purpose, 32, user1Context, logger);
        var bobKey = SecureKeyDerivation.DeriveKey(masterKey, purpose, 32, user2Context, logger);

        var contextTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[blue]User Context[/]")
            .AddColumn("[green]Derived Key[/]")
            .AddColumn("[yellow]Keys Match?[/]");

        var keysMatch = aliceKey.AsSpan().SequenceEqual(bobKey.AsSpan());

        contextTable.AddRow("user-alice", Convert.ToHexString(aliceKey)[..32] + "...", "");
        contextTable.AddRow("user-bob", Convert.ToHexString(bobKey)[..32] + "...", "");
        contextTable.AddRow("", "", keysMatch ? "[red]Yes (BAD!)[/]" : "[green]No (GOOD!)[/]");

        AnsiConsole.Write(contextTable);
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine($"[bold]Key Separation:[/] Context data ensures different users get different keys even with the same purpose.");
        AnsiConsole.MarkupLine($"[bold]Security:[/] This prevents one user from using another user's derived keys.");
        AnsiConsole.WriteLine();

        await Task.Delay(500);
    }

    /// <summary>
    /// Example showing the simplest possible API call for quick integration.
    /// </summary>
    private async Task SimpleApiExample(ILogger logger)
    {
        AnsiConsole.Write(new Rule("[cyan]Example 4: Simple API Call[/]").RuleStyle("cyan"));
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine("[bold]The simplest way to derive a key:[/]");
        AnsiConsole.WriteLine();

        // Show the code that would be used
        var codePanel = new Panel(
            new Markup(
                "[green]// Derive a 32-byte encryption key from a master key[/]\n" +
                "[yellow]var masterKey = Convert.FromHexString(\"0123...CDEF\");[/]\n" +
                "[yellow]var encryptionKey = SecureKeyDerivation.DeriveKey([/]\n" +
                "[yellow]    masterKey,[/]\n" +
                "[yellow]    \"encryption\",[/]\n" +
                "[yellow]    32);[/]\n" +
                "\n" +
                "[green]// That's it! The key is ready to use.[/]"))
            .Header("[blue]Code Example[/]")
            .BorderColor(Color.Blue);

        AnsiConsole.Write(codePanel);
        AnsiConsole.WriteLine();

        // Actually run the example
        var masterKey = Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
        var encryptionKey = SecureKeyDerivation.DeriveKey(masterKey, "encryption", 32);

        AnsiConsole.MarkupLine($"[bold]Result:[/] [yellow]{Convert.ToHexString(encryptionKey)}[/]");
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine("[dim]This is the minimal API - just provide a master key, purpose, and desired length.[/]");
        AnsiConsole.MarkupLine("[dim]The library handles all the cryptographic details according to NIST standards.[/]");

        await Task.Delay(500);
    }
}
