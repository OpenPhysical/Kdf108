using Kdf108.Examples.Commands;
using Kdf108.Examples.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;
using Spectre.Console.Cli;

namespace Kdf108.Examples;

/// <summary>The command-line definition and its services, shared by <c>Program</c> and the tests.</summary>
public static class ExampleApp
{
    /// <summary>
    /// Everything the commands need, resolved by constructor injection: the Kdf108 services (which log
    /// through the container's logging and never log secrets), the random source used to generate keys,
    /// and the key-agreement walkthrough built on top of them.
    /// </summary>
    public static IServiceCollection Services(LogLevel logLevel, SecureRandom? random = null) =>
        new ServiceCollection()
            .AddLogging(logging => logging.SetMinimumLevel(logLevel).AddSimpleConsole(options => options.SingleLine = true))
            .AddKdf108()
            .AddSingleton(random ?? new SecureRandom())
            .AddSingleton<KeyAgreementWalkthrough>();

    public static ITypeRegistrar Registrar(IServiceCollection services) => new TypeRegistrar(services);

    public static void Configure(IConfigurator config)
    {
        config.SetApplicationName("kdf108-examples");
        config.UseStrictParsing(); // a mistyped option is an error, not silently ignored
        config.AddCommand<DeriveKeyCommand>("derive-key")
            .WithDescription("Derive a key with SP 800-108 (counter, feedback, double-pipeline, or KMAC)")
            .WithExample("derive-key", "--label", "encryption", "--context", "user:42", "--bits", "256");
        config.AddCommand<KeyAgreementCommand>("key-agreement")
            .WithDescription("Agree on a key with SP 800-56A, derive it with SP 800-56C, and confirm it")
            .WithExample("key-agreement", "--family", "ecc", "--scheme", "hybrid", "--kdf", "two-step", "--confirm");
        config.AddCommand<VerifyVectorsCommand>("verify-vectors")
            .WithDescription("Check published NIST known answers byte for byte");
        config.ValidateExamples();
    }
}
