using System;
using System.Linq;
using Kdf108.Examples;
using Kdf108.Examples.Commands;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;
using Spectre.Console.Cli;
using Spectre.Console.Testing;

namespace Kdf108.Test.Examples;

/// <summary>
/// The example programs do what their documentation says. Command-line tests run the real app
/// definition and container with a <see cref="TestConsole"/> injected in place of the terminal,
/// then check exit codes and output.
/// </summary>
[TestFixture]
[Parallelizable(ParallelScope.All)]
public class ExampleTests
{
    private static (int ExitCode, string Output) Run(SecureRandom? random, params string[] args)
    {
        var console = new TestConsole().Width(250);
        var app = new CommandApp(ExampleApp.Registrar(ExampleApp.Services(LogLevel.None, random)));
        app.Configure(config =>
        {
            ExampleApp.Configure(config);
            config.ConfigureConsole(console);
        });
        int exitCode = app.Run(args);
        return (exitCode, console.Output);
    }

    private static (int ExitCode, string Output) Run(params string[] args) => Run(null, args);

    private static SecureRandom Seeded(long seed)
    {
        var random = SecureRandom.GetInstance("SHA256PRNG", autoSeed: false);
        random.SetSeed(seed);
        return random;
    }

    private static IServiceProvider Provider() => ExampleApp.Services(LogLevel.None).BuildServiceProvider();

    [Test]
    public void VerifyVectorsReportsEveryCheckAsPassing()
    {
        var (exitCode, output) = Run("verify-vectors");
        Assert.That(exitCode, Is.Zero, output);
        Assert.That(output, Does.Not.Contain("FAIL"));
        var services = Provider();
        int checks = VerifyVectorsCommand.Run(services.GetRequiredService<ISp800108Kdf>(), services.GetRequiredService<ISp80056CKdf>(),
            services.GetRequiredService<IEcKeyAgreement>()).Count;
        Assert.That(output.Split('\n').Count(line => line.Contains(" pass ")), Is.EqualTo(checks));
    }

    [Test]
    public void DeriveKeyPrintsTheDerivedKey()
    {
        var (exitCode, output) = Run("derive-key", "--key", "000102030405060708090A0B0C0D0E0F", "--mode", "feedback", "--bits", "9", "--label", "mac");
        Assert.That(exitCode, Is.Zero, output);
        string expected = Convert.ToHexString(DeriveKeyCommand.Derive(new Sp800108Kdf(), Convert.FromHexString("000102030405060708090A0B0C0D0E0F"),
            "feedback", "mac", "user:42", 9));
        Assert.That(output, Does.Contain($"9 bits: {expected}"));
    }

    // The random source comes from the container, so a seeded one makes a run reproducible.
    [Test]
    public void DeriveKeyUsesTheInjectedRandomSource()
    {
        var first = Run(Seeded(7), "derive-key");
        var second = Run(Seeded(7), "derive-key");
        var other = Run(Seeded(8), "derive-key");
        Assert.That(first.ExitCode, Is.Zero, first.Output);
        Assert.That(second.Output, Is.EqualTo(first.Output));
        Assert.That(other.Output, Is.Not.EqualTo(first.Output));
    }

    [Test]
    public void DeriveKeyRejectsAShortKeyWithoutFallingBackToADefault()
    {
        var (exitCode, output) = Run("derive-key", "--key", "00");
        Assert.That(exitCode, Is.EqualTo(1));
        Assert.That(output, Does.Contain("at least 16 bytes"));
    }

    // Library messages contain "[L]"-style brackets; they must be shown, not parsed as markup.
    [Test]
    public void ErrorMessagesAreEscaped()
    {
        var (exitCode, output) = Run("derive-key", "--mode", "kmac", "--bits", "9");
        Assert.That(exitCode, Is.EqualTo(1));
        Assert.That(output, Does.Contain("whole number of bytes"));
    }

    [Test]
    public void KeyAgreementPrintsMatchingConfirmedKeys()
    {
        var (exitCode, output) = Run("key-agreement", "--family", "ffc", "--scheme", "mqv1", "--kdf", "two-step", "--confirm");
        Assert.That(exitCode, Is.Zero, output);
        Assert.That(output, Does.Contain("Keys match").And.Contain("both tags verified"));
    }

    [Test]
    public void UnknownOptionsFailParsing() =>
        Assert.That(Run("derive-key", "--nope").ExitCode, Is.Not.Zero);

    [Test]
    public void BothPartiesDeriveTheSameConfirmedKey(
        [Values("ecc", "ffc")] string family,
        [Values("ephemeral", "static", "one-flow", "hybrid", "hybrid-one-flow", "mqv2", "mqv1")] string scheme,
        [Values("one-step", "two-step")] string kdf)
    {
        var result = Provider().GetRequiredService<KeyAgreementWalkthrough>().Run(family, scheme, kdf, confirm: true);
        Assert.That(result.KeyU, Is.EqualTo(result.KeyV));
        Assert.That(result.KeyU, Has.Length.EqualTo(32));
        Assert.That(result.TagsVerified, Is.True);
    }

    [TestCase("counter")]
    [TestCase("feedback")]
    [TestCase("double-pipeline")]
    [TestCase("kmac")]
    public void DeriveKeySeparatesLabelsAndContexts(string mode)
    {
        var kdf = new Sp800108Kdf();
        byte[] key = new byte[32];
        byte[] a = DeriveKeyCommand.Derive(kdf, key, mode, "encryption", "user:42", 256);
        Assert.That(DeriveKeyCommand.Derive(kdf, key, mode, "mac", "user:42", 256), Is.Not.EqualTo(a));
        Assert.That(DeriveKeyCommand.Derive(kdf, key, mode, "encryption", "user:43", 256), Is.Not.EqualTo(a));
    }
}
