using System.Threading.Tasks;
using Kdf108.Examples.Commands;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Kdf108.Examples;

class Program
{
    static async Task<int> Main(string[] args)
    {
        // Display header
        AnsiConsole.Write(
            new FigletText("KDF-108")
                .Centered()
                .Color(Color.Cyan1));
        
        AnsiConsole.MarkupLine("[dim]NIST SP 800-108, SP 800-56A/C Key Derivation Examples[/]");
        AnsiConsole.WriteLine();

        // Configure the CLI app
        var app = new CommandApp();
        app.Configure(config =>
        {
            config.SetApplicationName("kdf108");
            config.SetApplicationVersion("1.0.1");
            
            // Add commands
            config.AddCommand<DeriveKeyCommand>("derive-key")
                .WithDescription("Derive a key using SP 800-108 KDF")
                .WithExample(new[] { "derive-key", "--master-key", "0123456789ABCDEF", "--purpose", "encryption", "--output-length", "32" });
            
            
            config.AddCommand<SecureChannelCommand>("secure-channel")
                .WithDescription("Establish a secure channel using ECDH + KDF")
                .WithExample(new[] { "secure-channel", "--curve", "P-256", "--session-id", "test-session" });
            
            config.AddCommand<TestVectorCommand>("test-vectors")
                .WithDescription("Run NIST test vectors to validate implementation")
                .WithExample(new[] { "test-vectors", "--verbose" });
            
            config.AddCommand<BenchmarkCommand>("benchmark")
                .WithDescription("Benchmark KDF performance")
                .WithExample(new[] { "benchmark", "--iterations", "10000" });
            
            config.AddCommand<InteractiveCommand>("interactive")
                .WithDescription("Interactive wizard mode for beginners")
                .WithExample(new[] { "interactive" });
            
            
            config.AddCommand<MinimalExamplesCommand>("minimal")
                .WithDescription("Minimal working examples demonstrating core KDF functionality")
                .WithExample(new[] { "minimal" })
                .WithExample(new[] { "minimal", "--verbose" });
            
            config.AddCommand<ComplianceCheckCommand>("compliance-check")
                .WithDescription("Interactive NIST compliance checker for KDF configurations")
                .WithExample(new[] { "compliance-check" })
                .WithExample(new[] { "compliance-check", "--verbose" });

            // Configure validation
            config.ValidateExamples();
        });

        return await app.RunAsync(args);
    }
}
