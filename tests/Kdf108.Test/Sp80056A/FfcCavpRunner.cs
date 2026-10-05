using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using Kdf108.Domain.Sp80056A;
using NUnit.Framework;

namespace Kdf108.Test.Sp80056A;

/// <summary>Executes the FFC primitive portion of the SP 800-56A CAVP vectors.</summary>
internal static class FfcCavpRunner
{
    private static readonly ConcurrentDictionary<string, FfcDomain> Domains = new(StringComparer.Ordinal);

    internal static byte[] ComputeZ(CavpTestVector vector)
    {
        ArgumentNullException.ThrowIfNull(vector);
        if (vector.Source.Family != CavpFamily.Ffc)
            throw new ArgumentException("The vector is not an FFC CAVP vector.", nameof(vector));

        var domain = Domain(vector);

        return vector.Source.Scheme switch
        {
            "FFC Ephemeral Scheme" => FfcSchemes.DhEphemeral(
                EphemeralPair(vector, domain), EphemeralPublic(vector, domain, "CAVS")),
            "FFC Static Scheme" => FfcSchemes.DhStatic(
                StaticPair(vector, domain), StaticPublic(vector, domain, "CAVS")),
            "FFC OneFlow Scheme" or "FFC One Flow Scheme" => OneFlow(vector, domain),
            "FFC Hybrid1 Scheme" => FfcSchemes.DhHybrid1(
                StaticPair(vector, domain), EphemeralPair(vector, domain),
                StaticPublic(vector, domain, "CAVS"), EphemeralPublic(vector, domain, "CAVS")),
            "FFC Hybrid OneFlow Scheme" or "FFC Hybrid1Flow Scheme" => HybridOneFlow(vector, domain),
            "FFC MQV2 Scheme" => FfcSchemes.Mqv2(
                StaticPair(vector, domain), EphemeralPair(vector, domain),
                StaticPublic(vector, domain, "CAVS"), EphemeralPublic(vector, domain, "CAVS")),
            "FFC MQV1 Scheme" => Mqv1(vector, domain),
            _ => throw new NotSupportedException($"Unsupported FFC CAVP scheme '{vector.Source.Scheme}'.")
        };
    }

    /// <summary>
    /// Validates only the primitive-test shard. KDF and key-confirmation shards must validate
    /// their later-stage outputs, so treating a matching Z as their verdict would be unsafe.
    /// </summary>
    internal static void ValidateZzVector(CavpTestVector vector)
    {
        if (vector.Source.Stage != CavpStage.Zz)
            throw new InvalidOperationException("FFC Z validation is only a verdict for the ZZ-only CAVP stage.");

        byte[]? actual = null;
        Exception? failure = null;
        try
        {
            actual = ComputeZ(vector);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            failure = ex;
        }

        if (vector.ExpectPass)
        {
            Assert.That(failure, Is.Null, $"Passing FFC vector {vector.Count} must complete.");
            Assert.That(actual, Is.EqualTo(vector.Z), $"Passing FFC vector {vector.Count} must reproduce Z.");
        }
        else
        {
            Assert.That(failure is not null || vector.Z is null || !actual!.AsSpan().SequenceEqual(vector.Z), Is.True,
                $"Failing FFC vector {vector.Count}, code {vector.ResultCode}, must be rejected or disagree with Z.");
        }
    }

    private static byte[] OneFlow(CavpTestVector vector, FfcDomain domain) =>
        Has(vector, "XephemIUT")
            ? FfcSchemes.DhOneFlowAsPartyU(EphemeralPair(vector, domain), StaticPublic(vector, domain, "CAVS"))
            : FfcSchemes.DhOneFlowAsPartyV(StaticPair(vector, domain), EphemeralPublic(vector, domain, "CAVS"));

    private static byte[] HybridOneFlow(CavpTestVector vector, FfcDomain domain) =>
        Has(vector, "XephemIUT")
            ? FfcSchemes.DhHybridOneFlowAsPartyU(
                StaticPair(vector, domain), EphemeralPair(vector, domain), StaticPublic(vector, domain, "CAVS"))
            : FfcSchemes.DhHybridOneFlowAsPartyV(
                StaticPair(vector, domain), StaticPublic(vector, domain, "CAVS"), EphemeralPublic(vector, domain, "CAVS"));

    private static byte[] Mqv1(CavpTestVector vector, FfcDomain domain) =>
        Has(vector, "XephemIUT")
            ? FfcSchemes.Mqv1AsPartyU(
                StaticPair(vector, domain), EphemeralPair(vector, domain), StaticPublic(vector, domain, "CAVS"))
            : FfcSchemes.Mqv1AsPartyV(
                StaticPair(vector, domain), StaticPublic(vector, domain, "CAVS"), EphemeralPublic(vector, domain, "CAVS"));

    private static FfcStaticKeyPair StaticPair(CavpTestVector vector, FfcDomain domain)
    {
        var pair = FfcStaticKeyPair.FromPrivate(domain, Field(vector, "XstatIUT"));
        if (!pair.PublicKey.Export().AsSpan().SequenceEqual(Field(vector, "YstatIUT")))
            throw new InvalidOperationException("The IUT static key pair is inconsistent.");
        return pair;
    }

    private static FfcEphemeralKeyPair EphemeralPair(CavpTestVector vector, FfcDomain domain)
    {
        var pair = FfcEphemeralKeyPair.FromPrivate(domain, Field(vector, "XephemIUT"));
        if (!pair.PublicKey.Export().AsSpan().SequenceEqual(Field(vector, "YephemIUT")))
            throw new InvalidOperationException("The IUT ephemeral key pair is inconsistent.");
        return pair;
    }

    private static FfcStaticPublicKey StaticPublic(CavpTestVector vector, FfcDomain domain, string party) =>
        FfcStaticPublicKey.Import(domain, Field(vector, $"Ystat{party}"));

    private static FfcEphemeralPublicKey EphemeralPublic(CavpTestVector vector, FfcDomain domain, string party) =>
        FfcEphemeralPublicKey.Import(domain, Field(vector, $"Yephem{party}"));

    private static bool Has(CavpTestVector vector, string name) => vector.Fields.ContainsKey(name);

    private static FfcDomain Domain(CavpTestVector vector)
    {
        string p = TextField(vector, "P");
        string q = TextField(vector, "Q");
        string g = TextField(vector, "G");
        return Domains.GetOrAdd($"{p}|{q}|{g}", _ => FfcDomain.ImportFips186(
            Convert.FromHexString(p), Convert.FromHexString(q), Convert.FromHexString(g),
            FfcDomainAssurance.TrustedAuthority("NIST CAVP KAS 2016")));
    }

    private static byte[] Field(CavpTestVector vector, string name)
        => Convert.FromHexString(TextField(vector, name));

    private static string TextField(CavpTestVector vector, string name)
    {
        if (!vector.Fields.TryGetValue(name, out string? value))
            throw new InvalidOperationException($"FFC vector {vector.Count} is missing required field '{name}'.");
        return value;
    }
}

[TestFixture]
public sealed class FfcCavpRunnerTests
{
    [Test]
    public void EveryBundledFfcSchemeExecutesThroughProductionApi()
    {
        var project = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (project is not null && !project.GetFiles("Kdf108.Test.csproj").Any())
            project = project.Parent;
        if (project is null) throw new DirectoryNotFoundException("Could not locate the test project.");
        string root = Path.Combine(project.FullName, "res", "vectors", "SP800-56A",
            "KASTestVectorsFFC2016", "Test of 800-56A excluding KDF");

        foreach (string directory in Directory.EnumerateDirectories(root).OrderBy(path => path, StringComparer.Ordinal))
        {
            string file = Directory.EnumerateFiles(directory, "*.fax").OrderBy(path => path, StringComparer.Ordinal).First();
            var vector = CavpTestVectorParser.ParseFile(file).First(candidate => candidate.ExpectPass && candidate.ResultCode == 0);
            Assert.That(() => FfcCavpRunner.ValidateZzVector(vector), Throws.Nothing, Path.GetFileName(directory));
        }
    }

    [Test]
    public void LaterStagesCannotBeMistakenForZzConformance()
    {
        var vector = new CavpTestVector
        {
            Source = new CavpSourceMetadata("synthetic", CavpFamily.Ffc, CavpStage.KdfNoKeyConfirmation,
                "FFC Ephemeral Scheme", "initiator")
        };

        Assert.That(() => FfcCavpRunner.ValidateZzVector(vector),
            Throws.InvalidOperationException.With.Message.Contains("only a verdict for the ZZ-only"));
    }
}
