using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Kdf108.Domain.Sp80056A;
using Kdf108.Simple;
using Microsoft.Extensions.Logging;
using Spectre.Console;
using Spectre.Console.Cli;
using Org.BouncyCastle.Security;
using Kdf108.Examples.Infrastructure;

namespace Kdf108.Examples.Commands;

/// <summary>
/// Interactive wizard that guides users through key derivation scenarios
/// with step-by-step prompts and explanations.
/// </summary>
public class InteractiveCommand : AsyncCommand<InteractiveCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Enable verbose explanations during the wizard")]
        [CommandOption("-v|--verbose")]
        [DefaultValue(false)]
        public bool Verbose { get; init; }
    }

    public override async Task<int> ExecuteAsync([NotNull] CommandContext context, [NotNull] Settings settings, CancellationToken cancellationToken)
    {
        var loggerFactory = LoggingSetup.CreateLoggerFactory(settings.Verbose);
        var logger = loggerFactory.CreateLogger<InteractiveCommand>();

        AnsiConsole.Write(new FigletText("KDF Wizard")
            .Centered()
            .Color(Color.Cyan1));
        
        AnsiConsole.MarkupLine("[dim]Interactive step-by-step guide to key derivation[/]");
        AnsiConsole.WriteLine();

        try
        {
            await RunInteractiveWizard(settings, loggerFactory, logger);
            return 0;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during interactive wizard");
            AnsiConsole.Write(new Panel($"[red]Error:[/] {ex.Message}")
                .Header("[red]✗ Failed[/]")
                .BorderColor(Color.Red));
            return 1;
        }
    }

    private async Task RunInteractiveWizard(Settings settings, ILoggerFactory loggerFactory, ILogger logger)
    {
        bool continueRunning = true;
        
        while (continueRunning)
        {
            AnsiConsole.Clear();
            AnsiConsole.Write(new FigletText("KDF Wizard")
                .Centered()
                .Color(Color.Cyan1));
            
            AnsiConsole.MarkupLine("[dim]Interactive step-by-step guide to key derivation[/]");
            AnsiConsole.WriteLine();
            
            var choice = await SelectMainMenuOption();
            
            switch (choice)
            {
                case "basic":
                    await BasicKdfWizard(settings, logger);
                    break;
                case "ecdh":
                    await EcdhWizard(settings, loggerFactory, logger);
                    break;
                case "multi":
                    await MultiKeyWizard(settings, logger);
                    break;
                case "advanced":
                    await AdvancedConfigurationWizard(settings, loggerFactory, logger);
                    break;
                case "learn":
                    await LearningMode(settings);
                    break;
                case "exit":
                    continueRunning = false;
                    break;
            }
            
            if (continueRunning && choice != "learn")
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[dim]Press any key to return to the main menu...[/]");
                Console.ReadKey(true);
            }
        }
        
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[green]Thank you for using the KDF Wizard![/]");
    }

    private async Task<string> SelectMainMenuOption()
    {
        AnsiConsole.Write(new Rule("[cyan]Main Menu - Choose Your Adventure[/]").RuleStyle("cyan"));
        AnsiConsole.WriteLine();
        
        await Task.Delay(10); // Make method actually async
        
        var choice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold blue]What cryptographic journey would you like to embark on today?[/]")
                .PageSize(15)
                .MoreChoicesText("[grey](Use ↑/↓ arrow keys to navigate, Enter to select)[/]")
                .AddChoices(new[] {
                    "basic",
                    "ecdh", 
                    "multi",
                    "advanced",
                    "learn",
                    "exit"
                })
                .UseConverter(choice => choice switch
                {
                    "basic" => "Basic Key Derivation - Derive a single secure key from your master key using NIST SP 800-108",
                    "ecdh" => "Elliptic Curve Key Agreement - Simulate two parties establishing shared encryption keys using ECDH + KDF (NIST SP 800-56A)",
                    "multi" => "Multiple Key Generation - Generate multiple cryptographically independent keys for different purposes from one master key",
                    "advanced" => "Advanced Configuration - Deep dive into parameter configuration, custom curves, and advanced cryptographic options",
                    "learn" => "Interactive Learning Center - Explore the theory and best practices behind key derivation functions",
                    "exit" => "Exit Wizard",
                    _ => choice
                }));
        
        AnsiConsole.WriteLine();
        return choice;
    }

    private async Task BasicKdfWizard(Settings settings, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[green]Basic Key Derivation Wizard - NIST SP 800-108 Implementation[/]").RuleStyle("green"));
        AnsiConsole.WriteLine();
        
        if (settings.Verbose)
        {
            AnsiConsole.MarkupLine("[dim]This wizard will guide you through the process of securely deriving encryption keys[/]");
            AnsiConsole.MarkupLine("[dim]from a master key using NIST-approved algorithms. Each step demonstrates best practices[/]");
            AnsiConsole.MarkupLine("[dim]for cryptographic key derivation in accordance with NIST SP 800-108.[/]");
            AnsiConsole.WriteLine();
        }

        // Get master key with enhanced explanation
        AnsiConsole.MarkupLine("[bold yellow]Step 1: Master Key Source Selection[/]");
        AnsiConsole.MarkupLine("[dim]The master key is the foundation of all security. It should be at least 256 bits (32 bytes)[/]");
        AnsiConsole.MarkupLine("[dim]of high-quality random data. For production use, consider using a Hardware Security Module (HSM).[/]");
        AnsiConsole.WriteLine();
        
        var useRandomKey = AnsiConsole.Confirm(
            "[bold]Generate a cryptographically secure random master key for this demonstration?[/]\n" +
            "[dim](Recommended - uses .NET's cryptographically secure random number generator)[/]", 
            true);
        
        byte[] masterKey;
        if (useRandomKey)
        {
            masterKey = new byte[32];
            new SecureRandom().NextBytes(masterKey);
            AnsiConsole.MarkupLine($"[bold]Generated Master Key:[/] [yellow]{Convert.ToHexString(masterKey)}[/]");
        }
        else
        {
            var hexKey = AnsiConsole.Ask<string>(
                "[bold]Enter your master key in hexadecimal format (64 hex characters for 32 bytes):[/]\n" +
                "[dim]Example: 404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F[/]", 
                "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
            try
            {
                masterKey = Convert.FromHexString(hexKey);
                AnsiConsole.MarkupLine($"[bold]Using Your Master Key:[/] [yellow]{Convert.ToHexString(masterKey)}[/]");
            }
            catch
            {
                AnsiConsole.MarkupLine("[red]Invalid hex format detected. Using secure default key for safety.[/]");
                masterKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
            }
        }
        
        AnsiConsole.WriteLine();

        // Get purpose with enhanced explanation
        AnsiConsole.MarkupLine("[bold yellow]Step 2: Key Purpose Definition[/]");
        AnsiConsole.MarkupLine("[dim]The purpose (also called 'label' in NIST terminology) ensures that keys derived for different[/]");
        AnsiConsole.MarkupLine("[dim]purposes are cryptographically independent. This prevents accidental key reuse across different[/]");
        AnsiConsole.MarkupLine("[dim]security contexts. Examples: 'encryption', 'authentication', 'key-wrapping', 'digital-signature'[/]");
        AnsiConsole.WriteLine();
        
        var suggestedPurposes = new[] { "encryption", "authentication", "key-wrapping", "digital-signature", "session-key", "backup-encryption" };
        var purpose = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]What will this derived key be used for? (Choose a purpose that matches your intended use case)[/]")
                .AddChoices(suggestedPurposes)
                .AddChoices("custom")
                .UseConverter(p => p == "custom" ? "Custom purpose (I'll type my own)" : $"{p} - {GetPurposeDescription(p)}"));
                
        if (purpose == "custom")
        {
            purpose = AnsiConsole.Ask<string>(
                "[bold]Enter your custom purpose/label:[/]\n" +
                "[dim](Use lowercase, hyphens for spaces, be descriptive but concise)[/]", 
                "my-custom-purpose");
        }
        
        // Get output length with enhanced explanation
        AnsiConsole.MarkupLine("[bold yellow]Step 3: Output Key Length Selection[/]");
        AnsiConsole.MarkupLine("[dim]The output length determines how much key material you'll get. Choose based on your target[/]");
        AnsiConsole.MarkupLine("[dim]algorithm's requirements. More bytes = more security, but only if your algorithm can use them.[/]");
        AnsiConsole.MarkupLine("[dim]Common choices: 16 bytes (AES-128), 32 bytes (AES-256), 64 bytes (multiple keys or large keys)[/]");
        AnsiConsole.WriteLine();
        
        var outputLength = AnsiConsole.Prompt(
            new SelectionPrompt<int>()
                .Title("[bold]How many bytes of key material do you need for your cryptographic algorithm?[/]")
                .AddChoices(new[] { 16, 24, 32, 48, 64, 128 })
                .UseConverter(length => length switch
                {
                    16 => "16 bytes (128 bits) - Perfect for AES-128, most HMAC keys",
                    24 => "24 bytes (192 bits) - 3DES keys, some specialized algorithms",
                    32 => "32 bytes (256 bits) - AES-256, SHA-256 HMAC, ChaCha20 (most popular choice)", 
                    48 => "48 bytes (384 bits) - Large composite keys, multiple smaller keys",
                    64 => "64 bytes (512 bits) - SHA-512 HMAC, very large keys, or multiple 32-byte keys",
                    128 => "128 bytes (1024 bits) - Specialized applications, multiple diverse keys",
                    _ => $"{length} bytes ({length * 8} bits)"
                }));

        // Ask about context with enhanced explanation
        AnsiConsole.MarkupLine("[bold yellow]Step 4: Context Data Configuration (Advanced Security)[/]");
        AnsiConsole.MarkupLine("[dim]Context data adds an extra layer of security by making keys unique to specific situations.[/]");
        AnsiConsole.MarkupLine("[dim]Examples: user IDs, session identifiers, application versions, or domain-specific data.[/]");
        AnsiConsole.MarkupLine("[dim]This ensures that even with the same master key and purpose, different contexts produce different keys.[/]");
        AnsiConsole.WriteLine();
        
        var contextChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]How would you like to handle context data for additional key separation?[/]")
                .AddChoices(new[] { "none", "user-session", "application", "timestamp", "custom" })
                .UseConverter(choice => choice switch
                {
                    "none" => "No context - Keep it simple (keys depend only on master key + purpose)",
                    "user-session" => "User Session - Include user ID and session info (recommended for multi-user systems)",
                    "application" => "Application Context - Include app name and version (good for enterprise deployments)",
                    "timestamp" => "Timestamp - Include current date/time (creates time-based key rotation)",
                    "custom" => "Custom Context - I'll specify my own context data",
                    _ => choice
                }));
                
        byte[]? context = null;
        
        if (contextChoice != "none")
        {
            var contextString = contextChoice switch
            {
                "user-session" => AnsiConsole.Ask<string>(
                    "[bold]Enter user session context (e.g., 'user-alice-session-12345'):[/]", 
                    "user-alice-session-12345"),
                "application" => AnsiConsole.Ask<string>(
                    "[bold]Enter application context (e.g., 'myapp-v2.1.0-prod'):[/]", 
                    "myapp-v2.1.0-prod"),
                "timestamp" => DateTimeOffset.UtcNow.ToString("yyyy-MM-dd-HH"),
                "custom" => AnsiConsole.Ask<string>(
                    "[bold]Enter your custom context data:[/]\n" +
                    "[dim](This will be mixed into the key derivation to make keys unique to your context)[/]", 
                    "my-custom-context"),
                _ => ""
            };
            
            if (contextChoice == "timestamp")
            {
                AnsiConsole.MarkupLine($"[dim]Using timestamp context: {contextString}[/]");
            }
            
            context = System.Text.Encoding.UTF8.GetBytes(contextString);
        }

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[yellow]Performing Cryptographic Key Derivation Using NIST SP 800-108[/]").RuleStyle("yellow"));
        AnsiConsole.WriteLine();
        
        if (settings.Verbose)
        {
            AnsiConsole.MarkupLine("[dim]Now performing key derivation using HMAC-SHA256 in Counter Mode according to NIST SP 800-108.[/]");
            AnsiConsole.MarkupLine("[dim]The algorithm combines your master key, purpose, context, and output length requirements[/]");
            AnsiConsole.MarkupLine("[dim]into a cryptographically secure derived key that's unique to your specific parameters.[/]");
            AnsiConsole.WriteLine();
        }
        
        // Perform derivation with progress
        byte[] derivedKey = Array.Empty<byte>();
        
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Star)
            .SpinnerStyle(Style.Parse("green"))
            .StartAsync("[green]Performing cryptographic key derivation...[/]", async ctx =>
            {
                await Task.Delay(1500); // Dramatic pause for effect
                derivedKey = SecureKeyDerivation.DeriveKey(masterKey, purpose, outputLength, context, logger);
            });

        AnsiConsole.WriteLine();
        
        // Show results with enhanced presentation
        var resultTable = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Green)
            .AddColumn("[bold green]Parameter[/]")
            .AddColumn("[bold yellow]Value[/]")
            .AddColumn("[bold blue]Explanation[/]");
            
        resultTable.AddRow(
            "Master Key", 
            $"{Convert.ToHexString(masterKey)[..16]}... ({masterKey.Length} bytes)",
            "Source of cryptographic entropy");
        resultTable.AddRow(
            "Purpose/Label", 
            purpose,
            "Ensures key separation by use case");
        resultTable.AddRow(
            "Output Length", 
            $"{outputLength} bytes ({outputLength * 8} bits)",
            "Amount of key material generated");
        resultTable.AddRow(
            "Context Data", 
            context != null ? $"{System.Text.Encoding.UTF8.GetString(context)} [{context.Length} bytes]" : "None",
            "Additional separation parameter");
        resultTable.AddRow(
            "Algorithm", 
            "HMAC-SHA256 Counter Mode",
            "NIST SP 800-108 compliant KDF");
        resultTable.AddRow(
            "[bold]Derived Key[/]", 
            $"[yellow]{Convert.ToHexString(derivedKey)}[/]",
            "[green]Ready for cryptographic use![/]");
            
        var resultPanel = new Panel(resultTable)
            .Header("[green]Key Derivation Successfully Completed[/]")
            .BorderColor(Color.Green);
            
        AnsiConsole.Write(resultPanel);
        AnsiConsole.WriteLine();
        
        if (settings.Verbose)
        {
            AnsiConsole.MarkupLine("[bold cyan]Security Notes:[/]");
            AnsiConsole.MarkupLine("[dim]• This key derivation is deterministic - same inputs always produce the same output[/]");
            AnsiConsole.MarkupLine("[dim]• The derived key is cryptographically independent from keys with different purposes[/]");
            AnsiConsole.MarkupLine("[dim]• HMAC-SHA256 provides 256-bit security strength regardless of output length[/]");
            AnsiConsole.MarkupLine("[dim]• The algorithm is approved for use in FIPS 140-2 Level 1 and higher environments[/]");
        }
        
        // Offer to save or continue
        var nextAction = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]What would you like to do with this key?[/]")
                .AddChoices(new[] { "copy", "save", "another", "menu" })
                .UseConverter(choice => choice switch
                {
                    "copy" => "Copy key to clipboard (if supported)",
                    "save" => "Save key to a file",
                    "another" => "Derive another key with different parameters",
                    "menu" => "Return to main menu",
                    _ => choice
                }));
                
        switch (nextAction)
        {
            case "copy":
                AnsiConsole.MarkupLine("[yellow]Key copied to clipboard (simulated - copy manually from above)[/]");
                await Task.Delay(1000);
                break;
            case "save":
                AnsiConsole.MarkupLine("[yellow]In production, save securely to encrypted storage only![/]");
                await Task.Delay(1000);
                break;
            case "another":
                await BasicKdfWizard(settings, logger);
                return;
        }

        await Task.Delay(500);
    }
    
    private string GetPurposeDescription(string purpose)
    {
        return purpose switch
        {
            "encryption" => "Symmetric encryption keys (AES, ChaCha20)",
            "authentication" => "Message authentication codes (HMAC)",
            "key-wrapping" => "Wrapping/unwrapping other keys",
            "digital-signature" => "Digital signature applications",
            "session-key" => "Temporary session-specific keys",
            "backup-encryption" => "Long-term backup encryption",
            _ => "Custom cryptographic purpose"
        };
    }

    private async Task EcdhWizard(Settings settings, ILoggerFactory loggerFactory, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[yellow]ECDH Key Agreement + KDF Demonstration[/]").RuleStyle("yellow"));
        AnsiConsole.WriteLine();

        if (settings.Verbose)
        {
            AnsiConsole.MarkupLine("[dim]ECDH (Elliptic Curve Diffie-Hellman) allows two parties to establish[/]");
            AnsiConsole.MarkupLine("[dim]a shared secret over an insecure channel. We then use KDF to derive[/]");
            AnsiConsole.MarkupLine("[dim]actual encryption and authentication keys from that shared secret.[/]");
            AnsiConsole.WriteLine();
        }

        // Choose curve
        var curve = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]Choose an elliptic curve:[/]")
                .AddChoices(new[] { "P-256", "P-384", "P-521" })
                .UseConverter(c => c switch
                {
                    "P-256" => "P-256 (secp256r1) - Fast, widely supported",
                    "P-384" => "P-384 (secp384r1) - Higher security",
                    "P-521" => "P-521 (secp521r1) - Highest security",
                    _ => c
                }));

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold]Simulating key exchange between Alice and Bob...[/]");
        AnsiConsole.WriteLine();

        // Generate key pairs
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("[blue]Generating Alice's key pair...[/]", async ctx =>
            {
                await Task.Delay(500);
            });
            
        var aliceKeyPair = EcKeyPair.GenerateRandom(curve, loggerFactory.CreateLogger<EcKeyPair>());
        AnsiConsole.MarkupLine("[green]Alice's key pair generated[/]");
        
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("[blue]Generating Bob's key pair...[/]", async ctx =>
            {
                await Task.Delay(500);
            });
            
        var bobKeyPair = EcKeyPair.GenerateRandom(curve, loggerFactory.CreateLogger<EcKeyPair>());
        AnsiConsole.MarkupLine("[green]Bob's key pair generated[/]");
        AnsiConsole.WriteLine();

        // Show public keys (these would be exchanged)
        var exchangeTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[blue]Party[/]")
            .AddColumn("[green]Public Key (exchanged)[/]");
            
        exchangeTable.AddRow("Alice", Convert.ToHexString(aliceKeyPair.PublicKey.ToByteArray(false))[..32] + "...");
        exchangeTable.AddRow("Bob", Convert.ToHexString(bobKeyPair.PublicKey.ToByteArray(false))[..32] + "...");
        
        AnsiConsole.Write(exchangeTable);
        AnsiConsole.WriteLine();

        // Perform key agreement
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
        
        AnsiConsole.MarkupLine($"[bold]Shared Secret Match:[/] {(secretsMatch ? "[green]Yes[/]" : "[red]No[/]")}");
        AnsiConsole.MarkupLine($"[bold]Shared Secret:[/] {Convert.ToHexString(aliceSharedSecret.ToArray())[..32]}...");
        AnsiConsole.WriteLine();

        // Derive keys from shared secret
        AnsiConsole.MarkupLine("[bold]Deriving application keys from shared secret...[/]");
        
        var sharedSecretBytes = aliceSharedSecret.ToArray();
        var encryptionKey = SecureKeyDerivation.DeriveKey(sharedSecretBytes, "encryption", 32, null, logger);
        var authKey = SecureKeyDerivation.DeriveKey(sharedSecretBytes, "authentication", 32, null, logger);
        
        var keysTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[blue]Key Purpose[/]")
            .AddColumn("[green]Derived Key[/]")
            .AddColumn("[grey]Usage[/]");
            
        keysTable.AddRow("Encryption", Convert.ToHexString(encryptionKey)[..32] + "...", "AES-256-GCM");
        keysTable.AddRow("Authentication", Convert.ToHexString(authKey)[..32] + "...", "HMAC-SHA256");
        
        AnsiConsole.Write(keysTable);
        
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[green]Secure channel established! Alice and Bob now have shared encryption keys.[/]");

        await Task.Delay(1000);
    }

    private async Task MultiKeyWizard(Settings settings, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[magenta]Multiple Key Derivation Demonstration[/]").RuleStyle("magenta"));
        AnsiConsole.WriteLine();

        // Get number of keys
        var keyCount = AnsiConsole.Prompt(
            new SelectionPrompt<int>()
                .Title("[bold]How many different keys do you need?[/]")
                .AddChoices(new[] { 2, 3, 5, 8 }));

        // Get master key
        var masterKey = new byte[32];
        new SecureRandom().NextBytes(masterKey);
        AnsiConsole.MarkupLine($"[bold]Master Key:[/] {Convert.ToHexString(masterKey)}");
        AnsiConsole.WriteLine();

        // Define some common purposes
        var purposes = new[] { "encryption", "authentication", "key-wrapping", "session-id", "backup-key", "audit-key", "temp-key", "user-key" };
        var lengths = new[] { 32, 32, 16, 16, 32, 24, 16, 20 };

        AnsiConsole.MarkupLine("[bold]Deriving keys for different purposes...[/]");
        AnsiConsole.WriteLine();

        var multiTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[blue]Purpose[/]")
            .AddColumn("[green]Derived Key[/]")
            .AddColumn("[grey]Length[/]");

        for (int i = 0; i < keyCount; i++)
        {
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync($"[cyan]Deriving key {i + 1}/{keyCount}...[/]", async ctx =>
                {
                    await Task.Delay(300);
                });

            var key = SecureKeyDerivation.DeriveKey(masterKey, purposes[i], lengths[i], null, logger);
            multiTable.AddRow(purposes[i], Convert.ToHexString(key), $"{lengths[i]} bytes");
        }

        AnsiConsole.Write(multiTable);
        AnsiConsole.WriteLine();
        
        AnsiConsole.MarkupLine("[green]All keys derived successfully![/]");
        AnsiConsole.MarkupLine("[dim]Each key is cryptographically independent despite coming from the same master key.[/]");

        await Task.Delay(1000);
    }

    private async Task LearningMode(Settings settings)
    {
        AnsiConsole.Write(new Rule("[blue]KDF Learning Mode[/]").RuleStyle("blue"));
        AnsiConsole.WriteLine();

        var topics = new[]
        {
            "What is a Key Derivation Function (KDF)?",
            "Why use KDF instead of just using keys directly?",
            "What is SP 800-108?",
            "What is SP 800-56A?",
            "When should I use ECDH + KDF?",
            "How does counter mode work?",
            "What are best practices?"
        };

        var topic = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]What would you like to learn about?[/]")
                .PageSize(10)
                .AddChoices(topics));

        AnsiConsole.WriteLine();
        
        switch (Array.IndexOf(topics, topic))
        {
            case 0:
                AnsiConsole.MarkupLine("[bold yellow]What is a Key Derivation Function (KDF)?[/]");
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("A KDF is a cryptographic function that derives one or more secret keys from");
                AnsiConsole.MarkupLine("a secret value (like a master key or shared secret). It uses a pseudorandom");
                AnsiConsole.MarkupLine("function to transform the input into output keys of the desired length.");
                break;
                
            case 1:
                AnsiConsole.MarkupLine("[bold yellow]Why use KDF instead of just using keys directly?[/]");
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("• [green]Key Separation:[/] Different keys for different purposes");
                AnsiConsole.MarkupLine("• [green]Standardization:[/] Follows NIST specifications");
                AnsiConsole.MarkupLine("• [green]Flexibility:[/] Generate keys of any needed length");
                AnsiConsole.MarkupLine("• [green]Security:[/] Proper entropy distribution");
                break;
                
            case 2:
                AnsiConsole.MarkupLine("[bold yellow]What is SP 800-108?[/]");
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("NIST Special Publication 800-108 defines Key Derivation Functions (KDFs)");
                AnsiConsole.MarkupLine("using pseudorandom functions. It specifies three modes: Counter Mode,");
                AnsiConsole.MarkupLine("Feedback Mode, and Double-Pipeline Iteration Mode.");
                break;
                
            case 3:
                AnsiConsole.MarkupLine("[bold yellow]What is SP 800-56A?[/]");
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("NIST SP 800-56A covers key agreement schemes, particularly Elliptic Curve");
                AnsiConsole.MarkupLine("Diffie-Hellman (ECDH). It defines how two parties can establish a shared");
                AnsiConsole.MarkupLine("secret and then derive keys from it using approved KDF methods.");
                break;
                
            case 4:
                AnsiConsole.MarkupLine("[bold yellow]When should I use ECDH + KDF?[/]");
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("• [green]Key Agreement:[/] When two parties need to establish shared keys");
                AnsiConsole.MarkupLine("• [green]Perfect Forward Secrecy:[/] Each session gets unique keys");
                AnsiConsole.MarkupLine("• [green]Public Key Infrastructure:[/] When you have PKI available");
                AnsiConsole.MarkupLine("• [green]Standards Compliance:[/] FIPS 140-2, Common Criteria, etc.");
                break;
                
            case 5:
                AnsiConsole.MarkupLine("[bold yellow]How does counter mode work?[/]");
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("Counter mode uses a PRF (like HMAC) with an incrementing counter.");
                AnsiConsole.MarkupLine("For each block: PRF(Key, Counter || Label || 0x00 || Context || OutputLength)");
                AnsiConsole.MarkupLine("The counter ensures each block is unique, and concatenating blocks");
                AnsiConsole.MarkupLine("gives you the final derived key of any desired length.");
                break;
                
            case 6:
                AnsiConsole.MarkupLine("[bold yellow]What are best practices?[/]");
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("• [green]Use different purposes/labels for different keys[/]");
                AnsiConsole.MarkupLine("• [green]Include context data when possible[/]");
                AnsiConsole.MarkupLine("• [green]Use sufficient master key entropy (256+ bits)[/]");
                AnsiConsole.MarkupLine("• [green]Follow NIST recommendations for PRF selection[/]");
                AnsiConsole.MarkupLine("• [green]Validate inputs and fail fast[/]");
                break;
        }
        
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[dim]Press any key to continue...[/]");
        Console.ReadKey(true);
        
        await Task.Delay(100);
    }

    private async Task AdvancedConfigurationWizard(Settings settings, ILoggerFactory loggerFactory, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[red]Advanced Configuration Wizard - Expert Cryptographic Parameter Control[/]").RuleStyle("red"));
        AnsiConsole.WriteLine();
        
        AnsiConsole.MarkupLine("[bold red]WARNING: Expert Mode Active[/]");
        AnsiConsole.MarkupLine("[dim]This wizard provides direct access to low-level cryptographic parameters.[/]");
        AnsiConsole.MarkupLine("[dim]Incorrect configuration can compromise security. Proceed only if you understand the implications.[/]");
        AnsiConsole.WriteLine();
        
        var proceed = AnsiConsole.Confirm(
            "[bold]Do you understand the security implications and wish to proceed with advanced configuration?[/]", 
            false);
            
        if (!proceed)
        {
            AnsiConsole.MarkupLine("[green]Returning to main menu.[/]");
            return;
        }
        
        AnsiConsole.WriteLine();
        
        // Select the type of advanced configuration
        var configType = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]What type of advanced configuration would you like to explore?[/]")
                .AddChoices(new[] { "kdf-modes", "prf-selection", "curve-config", "custom-params" })
                .UseConverter(choice => choice switch
                {
                    "kdf-modes" => "KDF Mode Comparison - Explore Counter, Feedback, and Double-Pipeline modes",
                    "prf-selection" => "PRF Algorithm Selection - Compare HMAC-SHA256, SHA384, SHA512, and CMAC",
                    "curve-config" => "Elliptic Curve Configuration - Deep dive into curve parameters and security levels",
                    "custom-params" => "Custom Parameter Entry - Direct parameter specification for experts",
                    _ => choice
                }));
                
        switch (configType)
        {
            case "kdf-modes":
                await ExploreKdfModes(settings, logger);
                break;
            case "prf-selection":
                await ExplorePrfAlgorithms(settings, logger);
                break;
            case "curve-config":
                await ExploreCurveConfiguration(settings, loggerFactory, logger);
                break;
            case "custom-params":
                await CustomParameterEntry(settings, loggerFactory, logger);
                break;
        }
    }
    
    private async Task ExploreKdfModes(Settings settings, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[cyan]KDF Mode Deep Dive - NIST SP 800-108 Implementation Comparison[/]").RuleStyle("cyan"));
        AnsiConsole.WriteLine();
        
        AnsiConsole.MarkupLine("[bold]NIST SP 800-108 defines three distinct KDF modes:[/]");
        AnsiConsole.WriteLine();
        
        var modeTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold blue]Mode[/]")
            .AddColumn("[bold green]Description[/]")
            .AddColumn("[bold yellow]Best For[/]")
            .AddColumn("[bold red]Security Notes[/]");
            
        modeTable.AddRow(
            "Counter Mode",
            "Uses incrementing counter with PRF",
            "General purpose, high performance",
            "Most widely implemented and tested");
        modeTable.AddRow(
            "Feedback Mode",
            "Chains output back as input",
            "Sequential key generation",
            "Requires careful IV handling");
        modeTable.AddRow(
            "Double-Pipeline",
            "Two-stage derivation process",
            "High-security environments",
            "Added complexity, slower performance");
            
        AnsiConsole.Write(modeTable);
        AnsiConsole.WriteLine();
        
        var selectedMode = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]Which mode would you like to demonstrate?[/]")
                .AddChoices(new[] { "counter", "feedback", "double-pipeline", "compare" })
                .UseConverter(choice => choice switch
                {
                    "counter" => "Counter Mode - Standard implementation (recommended)",
                    "feedback" => "Feedback Mode - Sequential chaining approach",
                    "double-pipeline" => "Double-Pipeline - Maximum security implementation",
                    "compare" => "Compare All - Generate same key with all three modes",
                    _ => choice
                }));
        
        // Generate demonstration based on selection
        var masterKey = new byte[32];
        new SecureRandom().NextBytes(masterKey);
        var purpose = "demo-mode-comparison";
        var outputLength = 32;
        
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[bold]Demonstration Parameters:[/]");
        AnsiConsole.MarkupLine($"[dim]Master Key: {Convert.ToHexString(masterKey)[..16]}...[/]");
        AnsiConsole.MarkupLine($"[dim]Purpose: {purpose}[/]");
        AnsiConsole.MarkupLine($"[dim]Output Length: {outputLength} bytes[/]");
        AnsiConsole.WriteLine();
        
        if (selectedMode == "compare")
        {
            AnsiConsole.MarkupLine("[bold yellow]⚠️ Note: Our library currently implements Counter Mode (NIST standard default)[/]");
            AnsiConsole.MarkupLine("[dim]All three modes would produce different outputs with the same inputs.[/]");
            AnsiConsole.MarkupLine("[dim]Counter Mode is the most widely supported and recommended for general use.[/]");
        }
        
        // Demonstrate counter mode (what we actually have)
        var derivedKey = SecureKeyDerivation.DeriveKey(masterKey, purpose, outputLength, null, logger);
        
        var resultTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold]Implementation[/]")
            .AddColumn("[bold]Output Key[/]")
            .AddColumn("[bold]Status[/]");
            
        resultTable.AddRow(
            "Counter Mode (Active)",
            Convert.ToHexString(derivedKey),
            "[green]Available[/]");
        resultTable.AddRow(
            "Feedback Mode",
            "Would produce different output",
            "[yellow]Specification only[/]");
        resultTable.AddRow(
            "Double-Pipeline Mode",
            "Would produce different output",
            "[yellow]Specification only[/]");
            
        AnsiConsole.Write(resultTable);
        
        await Task.Delay(1000);
    }
    
    private async Task ExplorePrfAlgorithms(Settings settings, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[magenta]Pseudorandom Function (PRF) Algorithm Deep Dive[/]").RuleStyle("magenta"));
        AnsiConsole.WriteLine();
        
        AnsiConsole.MarkupLine("[bold]PRF algorithms form the cryptographic core of key derivation:[/]");
        AnsiConsole.WriteLine();
        
        var prfTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold blue]PRF Algorithm[/]")
            .AddColumn("[bold green]Security Strength[/]")
            .AddColumn("[bold yellow]Performance[/]")
            .AddColumn("[bold cyan]Use Cases[/]");
            
        prfTable.AddRow(
            "HMAC-SHA256",
            "256 bits",
            "Fast",
            "General purpose, most common");
        prfTable.AddRow(
            "HMAC-SHA384",
            "384 bits",
            "Medium",
            "Higher security requirements");
        prfTable.AddRow(
            "HMAC-SHA512",
            "512 bits",
            "Slower",
            "Maximum security, large keys");
        prfTable.AddRow(
            "AES-CMAC",
            "128/256 bits",
            "Hardware optimized",
            "Embedded systems, AES acceleration");
            
        AnsiConsole.Write(prfTable);
        AnsiConsole.WriteLine();
        
        AnsiConsole.MarkupLine("[bold yellow]Current Implementation:[/] Our library uses HMAC-SHA256 (industry standard)");
        AnsiConsole.MarkupLine("[dim]This provides 256-bit security strength and excellent performance across all platforms.[/]");
        AnsiConsole.MarkupLine("[dim]HMAC-SHA256 is approved for FIPS 140-2 and is the most widely adopted PRF for KDF operations.[/]");
        
        await Task.Delay(1000);
    }
    
    private async Task ExploreCurveConfiguration(Settings settings, ILoggerFactory loggerFactory, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[green]Elliptic Curve Deep Configuration - NIST P-Curves and Security Analysis[/]").RuleStyle("green"));
        AnsiConsole.WriteLine();
        
        AnsiConsole.MarkupLine("[bold]Elliptic Curve selection impacts both security and performance:[/]");
        AnsiConsole.WriteLine();
        
        var curveTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold blue]Curve[/]")
            .AddColumn("[bold green]Key Size[/]")
            .AddColumn("[bold yellow]Security Level[/]")
            .AddColumn("[bold cyan]Performance[/]")
            .AddColumn("[bold red]Quantum Resistance[/]");
            
        curveTable.AddRow("P-256 (secp256r1)", "256 bits", "128-bit equivalent", "Fast", "~2030 vulnerable");
        curveTable.AddRow("P-384 (secp384r1)", "384 bits", "192-bit equivalent", "Medium", "~2040 vulnerable");
        curveTable.AddRow("P-521 (secp521r1)", "521 bits", "256-bit equivalent", "Slower", "~2050 vulnerable");
        
        AnsiConsole.Write(curveTable);
        AnsiConsole.WriteLine();
        
        var selectedCurve = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]Select a curve for detailed analysis and key generation:[/]")
                .AddChoices(new[] { "P-256", "P-384", "P-521" })
                .UseConverter(curve => curve switch
                {
                    "P-256" => "P-256 - Best balance of security and performance (recommended for most applications)",
                    "P-384" => "P-384 - Enhanced security for sensitive applications",
                    "P-521" => "P-521 - Maximum current security (future-proofing)",
                    _ => curve
                }));
        
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[bold]Analyzing {selectedCurve}:[/]");
        
        var analysisTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold]Property[/]")
            .AddColumn("[bold]Value[/]")
            .AddColumn("[bold]Explanation[/]");
            
        switch (selectedCurve)
        {
            case "P-256":
                analysisTable.AddRow("NIST Name", "P-256", "256-bit prime field curve");
                analysisTable.AddRow("RFC Name", "secp256r1", "Standard elliptic curve identifier");
                analysisTable.AddRow("Field Size", "256 bits", "Size of the underlying finite field");
                analysisTable.AddRow("Security", "~128 bits", "Equivalent symmetric key strength");
                analysisTable.AddRow("Key Size", "32 bytes private, 65 bytes public", "Actual key material sizes");
                analysisTable.AddRow("Performance", "~2000 ops/sec", "Typical signing operations per second");
                break;
            case "P-384":
                analysisTable.AddRow("NIST Name", "P-384", "384-bit prime field curve");
                analysisTable.AddRow("RFC Name", "secp384r1", "Standard elliptic curve identifier");
                analysisTable.AddRow("Field Size", "384 bits", "Size of the underlying finite field");
                analysisTable.AddRow("Security", "~192 bits", "Equivalent symmetric key strength");
                analysisTable.AddRow("Key Size", "48 bytes private, 97 bytes public", "Actual key material sizes");
                analysisTable.AddRow("Performance", "~800 ops/sec", "Typical signing operations per second");
                break;
            case "P-521":
                analysisTable.AddRow("NIST Name", "P-521", "521-bit prime field curve");
                analysisTable.AddRow("RFC Name", "secp521r1", "Standard elliptic curve identifier");
                analysisTable.AddRow("Field Size", "521 bits", "Size of the underlying finite field");
                analysisTable.AddRow("Security", "~256 bits", "Equivalent symmetric key strength");
                analysisTable.AddRow("Key Size", "66 bytes private, 133 bytes public", "Actual key material sizes");
                analysisTable.AddRow("Performance", "~300 ops/sec", "Typical signing operations per second");
                break;
        }
        
        AnsiConsole.Write(analysisTable);
        AnsiConsole.WriteLine();
        
        // Demonstrate key generation with selected curve
        var generateDemo = AnsiConsole.Confirm($"[bold]Generate a demonstration key pair using {selectedCurve}?[/]", true);
        
        if (generateDemo)
        {
            AnsiConsole.MarkupLine("[bold]Generating key pair...[/]");
            
            var keyPair = EcKeyPair.GenerateRandom(selectedCurve, loggerFactory.CreateLogger<EcKeyPair>());
            
            var keyTable = new Table()
                .Border(TableBorder.Rounded)
                .AddColumn("[bold]Key Component[/]")
                .AddColumn("[bold]Value[/]");
                
            keyTable.AddRow("Curve", selectedCurve);
            keyTable.AddRow("Private Key", Convert.ToHexString(keyPair.PrivateKey.ToByteArray())[..32] + "...");
            keyTable.AddRow("Public Key (X)", Convert.ToHexString(keyPair.PublicKey.ToByteArray(false))[..32] + "...");
            keyTable.AddRow("Compressed Public Key", Convert.ToHexString(keyPair.PublicKey.ToByteArray(true))[..32] + "...");
            
            AnsiConsole.Write(keyTable);
        }
        
        await Task.Delay(1000);
    }
    
    private async Task CustomParameterEntry(Settings settings, ILoggerFactory loggerFactory, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[red]Custom Parameter Entry - Expert Direct Configuration[/]").RuleStyle("red"));
        AnsiConsole.WriteLine();
        
        AnsiConsole.MarkupLine("[bold red]EXPERT MODE: Direct cryptographic parameter specification[/]");
        AnsiConsole.MarkupLine("[dim]This interface allows direct specification of all cryptographic parameters.[/]");
        AnsiConsole.MarkupLine("[dim]Incorrect values can result in weak keys or cryptographic failures.[/]");
        AnsiConsole.WriteLine();
        
        // Master key entry
        var masterKeyHex = AnsiConsole.Ask<string>(
            "[bold]Enter master key (hex format, recommend 256+ bits):[/]\n" +
            "[dim]Example: 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F[/]",
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
            
        byte[] masterKey;
        try
        {
            masterKey = Convert.FromHexString(masterKeyHex);
            AnsiConsole.MarkupLine($"[green]Master key accepted: {masterKey.Length} bytes ({masterKey.Length * 8} bits)[/]");
        }
        catch
        {
            AnsiConsole.MarkupLine("[red]Invalid hex format. Using default key.[/]");
            masterKey = Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        }
        
        // Purpose string
        var purpose = AnsiConsole.Ask<string>(
            "[bold]Enter purpose/label string:[/]\n" +
            "[dim]This should be unique for each key use case[/]",
            "expert-custom-key");
            
        // Output length
        var outputLength = AnsiConsole.Ask<int>(
            "[bold]Enter output length in bytes (1-1024):[/]\n" +
            "[dim]Common values: 16 (AES-128), 32 (AES-256), 64 (large keys)[/]",
            32);
            
        if (outputLength < 1 || outputLength > 1024)
        {
            AnsiConsole.MarkupLine("[yellow]Output length clamped to safe range[/]");
            outputLength = Math.Clamp(outputLength, 1, 1024);
        }
        
        // Context data
        var useContext = AnsiConsole.Confirm("[bold]Include custom context data?[/]", false);
        byte[]? context = null;
        
        if (useContext)
        {
            var contextHex = AnsiConsole.Ask<string>(
                "[bold]Enter context data (hex format):[/]\n" +
                "[dim]Example: 41424344 (ASCII 'ABCD')[/]",
                "41424344");
                
            try
            {
                context = Convert.FromHexString(contextHex);
                AnsiConsole.MarkupLine($"[green]Context accepted: {context.Length} bytes[/]");
            }
            catch
            {
                AnsiConsole.MarkupLine("[red]Invalid hex format. Using ASCII conversion.[/]");
                context = System.Text.Encoding.ASCII.GetBytes(contextHex);
            }
        }
        
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold]Performing custom key derivation...[/]");
        
        var derivedKey = SecureKeyDerivation.DeriveKey(masterKey, purpose, outputLength, context, logger);
        
        // Show detailed results
        var resultTable = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Red)
            .AddColumn("[bold red]Parameter[/]")
            .AddColumn("[bold yellow]Input Value[/]")
            .AddColumn("[bold green]Result/Status[/]");
            
        resultTable.AddRow("Master Key", $"{Convert.ToHexString(masterKey)[..32]}...", $"{masterKey.Length} bytes entropy");
        resultTable.AddRow("Purpose/Label", purpose, $"{System.Text.Encoding.UTF8.GetBytes(purpose).Length} bytes");
        resultTable.AddRow("Output Length", $"{outputLength} bytes", $"{outputLength * 8} bits generated");
        resultTable.AddRow("Context", context != null ? Convert.ToHexString(context) : "None", context?.Length.ToString() + " bytes" ?? "N/A");
        resultTable.AddRow("Algorithm", "HMAC-SHA256 Counter Mode", "NIST SP 800-108 compliant");
        resultTable.AddRow("[bold]Derived Key[/]", $"[yellow]{Convert.ToHexString(derivedKey)}[/]", "[green]Generated[/]");
        
        AnsiConsole.Write(resultTable);
        
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold cyan]Expert Validation Notes:[/]");
        AnsiConsole.MarkupLine($"[dim]• Master key entropy: {masterKey.Length * 8} bits (recommend ≥256)[/]");
        AnsiConsole.MarkupLine($"[dim]• Purpose uniqueness: Ensure '{purpose}' is unique per use case[/]");
        AnsiConsole.MarkupLine($"[dim]• Output security: Limited by min(master_key_entropy, 256) = {Math.Min(masterKey.Length * 8, 256)} bits[/]");
        if (context != null)
        {
            AnsiConsole.MarkupLine($"[dim]• Context separation: {context.Length} bytes of additional domain separation[/]");
        }
        
        await Task.Delay(1000);
    }
}
