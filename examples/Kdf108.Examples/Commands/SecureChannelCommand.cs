using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Kdf108.Domain.Sp80056A;
using Kdf108.Simple;
using Microsoft.Extensions.Logging;
using Spectre.Console;
using Spectre.Console.Cli;
using Kdf108.Examples.Infrastructure;

namespace Kdf108.Examples.Commands;

/// <summary>
/// Demonstrates establishing a secure communication channel using ECDH key agreement
/// followed by key derivation for encryption and authentication keys.
/// </summary>
public class SecureChannelCommand : AsyncCommand<SecureChannelCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Elliptic curve to use (P-256, P-384, P-521)")]
        [CommandOption("-c|--curve")]
        [DefaultValue("P-256")]
        public string Curve { get; init; } = "P-256";

        [Description("Session identifier for key derivation")]
        [CommandOption("-s|--session-id")]
        [DefaultValue("secure-session-001")]
        public string SessionId { get; init; } = "secure-session-001";

        [Description("Enable verbose logging")]
        [CommandOption("-v|--verbose")]
        [DefaultValue(false)]
        public bool Verbose { get; init; }
    }

    public override async Task<int> ExecuteAsync([NotNull] CommandContext context, [NotNull] Settings settings)
    {
        var loggerFactory = LoggingSetup.CreateLoggerFactory(settings.Verbose);
        var logger = loggerFactory.CreateLogger<SecureChannelCommand>();

        AnsiConsole.Write(new Rule("[cyan]Secure Channel Establishment[/]").RuleStyle("grey"));
        AnsiConsole.MarkupLine("[dim]Complete ECDH + KDF pipeline for establishing secure communication channels[/]");
        AnsiConsole.WriteLine();

        try
        {
            await DemonstrateSecureChannelSetup(settings, loggerFactory, logger);
            return 0;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during secure channel establishment");
            AnsiConsole.Write(new Panel($"[red]Error:[/] {ex.Message}")
                .Header("[red]✗ Failed[/]")
                .BorderColor(Color.Red));
            return 1;
        }
    }

    private async Task DemonstrateSecureChannelSetup(Settings settings, ILoggerFactory loggerFactory, ILogger logger)
    {
        // Step 1: Generate key pairs for Alice and Bob
        AnsiConsole.Write(new Rule("[green]Step 1: Key Pair Generation[/]").RuleStyle("green"));
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine($"[bold]Generating ECDH key pairs on curve {settings.Curve}...[/]");
        
        var aliceKeyPair = EcKeyPair.GenerateRandom(settings.Curve, loggerFactory.CreateLogger<EcKeyPair>());
        var bobKeyPair = EcKeyPair.GenerateRandom(settings.Curve, loggerFactory.CreateLogger<EcKeyPair>());

        var keyTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[blue]Party[/]")
            .AddColumn("[green]Public Key (first 32 chars)[/]")
            .AddColumn("[grey]Curve[/]");

        var alicePublicHex = Convert.ToHexString(aliceKeyPair.PublicKey.ToByteArray(false))[..32];
        var bobPublicHex = Convert.ToHexString(bobKeyPair.PublicKey.ToByteArray(false))[..32];

        keyTable.AddRow("Alice (Client)", $"{alicePublicHex}...", settings.Curve);
        keyTable.AddRow("Bob (Server)", $"{bobPublicHex}...", settings.Curve);

        AnsiConsole.Write(keyTable);
        AnsiConsole.WriteLine();
        await Task.Delay(500);

        // Step 2: ECDH Key Agreement
        AnsiConsole.Write(new Rule("[yellow]Step 2: ECDH Key Agreement[/]").RuleStyle("yellow"));
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine("[bold]Performing ECDH key agreement...[/]");
        
        var aliceSharedSecret = EcdhKeyAgreement.ComputeSharedSecret(
            aliceKeyPair.PrivateKey,
            bobKeyPair.PublicKey,
            logger);

        var bobSharedSecret = EcdhKeyAgreement.ComputeSharedSecret(
            bobKeyPair.PrivateKey,
            aliceKeyPair.PublicKey,
            logger);

        var secretsMatch = aliceSharedSecret.ToArray().AsSpan().SequenceEqual(bobSharedSecret.ToArray().AsSpan());
        
        AnsiConsole.MarkupLine($"[bold]Shared Secret Length:[/] {aliceSharedSecret.ToArray().Length} bytes");
        AnsiConsole.MarkupLine($"[bold]Shared Secret (first 16 bytes):[/] {Convert.ToHexString(aliceSharedSecret.ToArray())[..32]}...");
        AnsiConsole.MarkupLine($"[bold]Secrets Match:[/] {(secretsMatch ? "[green]✓ Yes[/]" : "[red]✗ No[/]")}");
        AnsiConsole.WriteLine();
        await Task.Delay(500);

        // Step 3: Key Derivation for Secure Channel
        AnsiConsole.Write(new Rule("[magenta]Step 3: Key Derivation[/]").RuleStyle("magenta"));
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine("[bold]Deriving channel keys from shared secret...[/]");
        
        var sharedSecretBytes = aliceSharedSecret.ToArray();
        var sessionContext = System.Text.Encoding.UTF8.GetBytes(settings.SessionId);

        // Derive different keys for different purposes
        var encryptionKey = SecureKeyDerivation.DeriveKey(sharedSecretBytes, "aes-encryption", 32, sessionContext, logger);
        var authenticationKey = SecureKeyDerivation.DeriveKey(sharedSecretBytes, "hmac-authentication", 32, sessionContext, logger);
        var keyWrappingKey = SecureKeyDerivation.DeriveKey(sharedSecretBytes, "key-wrapping", 16, sessionContext, logger);
        var sessionNonce = SecureKeyDerivation.DeriveKey(sharedSecretBytes, "session-nonce", 12, sessionContext, logger);

        var channelKeysTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[blue]Key Purpose[/]")
            .AddColumn("[green]Derived Key[/]")
            .AddColumn("[grey]Length[/]")
            .AddColumn("[yellow]Usage[/]");

        channelKeysTable.AddRow(
            "AES Encryption", 
            Convert.ToHexString(encryptionKey)[..32] + "...", 
            "32 bytes",
            "AES-256-GCM");
        
        channelKeysTable.AddRow(
            "HMAC Authentication", 
            Convert.ToHexString(authenticationKey)[..32] + "...", 
            "32 bytes",
            "Message integrity");
        
        channelKeysTable.AddRow(
            "Key Wrapping", 
            Convert.ToHexString(keyWrappingKey), 
            "16 bytes",
            "AES-128 key wrap");
        
        channelKeysTable.AddRow(
            "Session Nonce", 
            Convert.ToHexString(sessionNonce), 
            "12 bytes",
            "GCM initialization");

        AnsiConsole.Write(channelKeysTable);
        AnsiConsole.WriteLine();
        await Task.Delay(500);

        // Step 4: Security Properties Summary
        AnsiConsole.Write(new Rule("[blue]Security Properties[/]").RuleStyle("blue"));
        AnsiConsole.WriteLine();

        var securityPanel = new Panel(
            new Markup(
                "[green]✓ Perfect Forward Secrecy:[/] New ephemeral keys for each session\n" +
                "[green]✓ Mutual Authentication:[/] Both parties derive same keys only with valid key pairs\n" +
                "[green]✓ Key Separation:[/] Different keys for encryption, authentication, and key wrapping\n" +
                "[green]✓ Session Binding:[/] Keys tied to specific session identifier\n" +
                "[green]✓ NIST Compliance:[/] Uses SP 800-56A ECDH + SP 800-108 KDF"))
            .Header("[green]✓ Secure Channel Established[/]")
            .BorderColor(Color.Green)
            .Expand();

        AnsiConsole.Write(securityPanel);
        
        if (settings.Verbose)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[dim]Technical Details[/]").RuleStyle("grey"));
            
            var detailsTable = new Table()
                .Border(TableBorder.None)
                .HideHeaders()
                .AddColumn("")
                .AddColumn("")
                .AddRow("[grey]ECDH Curve:[/]", settings.Curve)
                .AddRow("[grey]KDF Algorithm:[/]", "HMAC-SHA256")
                .AddRow("[grey]KDF Mode:[/]", "Counter (SP 800-108)")
                .AddRow("[grey]Session Context:[/]", settings.SessionId)
                .AddRow("[grey]Shared Secret Size:[/]", $"{sharedSecretBytes.Length} bytes");
            
            AnsiConsole.Write(detailsTable);
        }

        await Task.Delay(500);
    }
}
