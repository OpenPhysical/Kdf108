using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Kdf108.Test.Support;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Test.Nist80056A;

/// <summary>
/// Executes every vector of the NIST CAVP SP 800-56A KAS 2016 corpus through the public API:
/// Z through <see cref="EcSchemes"/>/<see cref="FfcSchemes"/>, DKM through
/// <see cref="Sp80056C.OneStep"/>, and tags through <see cref="KeyConfirmation"/>.
/// One test per file; six disjoint shards.
/// </summary>
[TestFixture]
[Category("CAVP")]
[Parallelizable(ParallelScope.All)]
public class KasCavpTests
{
    [TestCaseSource(nameof(EccZzFiles)), Category("CAVP-SP800-56A-ECC-ZZ")] public void EccZz(string file) => Run(file);
    [TestCaseSource(nameof(EccKdfFiles)), Category("CAVP-SP800-56A-ECC-KDF")] public void EccKdf(string file) => Run(file);
    [TestCaseSource(nameof(EccKcFiles)), Category("CAVP-SP800-56A-ECC-KC")] public void EccKc(string file) => Run(file);
    [TestCaseSource(nameof(FfcZzFiles)), Category("CAVP-SP800-56A-FFC-ZZ")] public void FfcZz(string file) => Run(file);
    [TestCaseSource(nameof(FfcKdfFiles)), Category("CAVP-SP800-56A-FFC-KDF")] public void FfcKdf(string file) => Run(file);
    [TestCaseSource(nameof(FfcKcFiles)), Category("CAVP-SP800-56A-FFC-KC")] public void FfcKc(string file) => Run(file);

    private static IEnumerable<TestCaseData> EccZzFiles() => Files("ECC", "Test of 800-56A excluding KDF");
    private static IEnumerable<TestCaseData> EccKdfFiles() => Files("ECC", "No Key Confirmation");
    private static IEnumerable<TestCaseData> EccKcFiles() => Files("ECC", "Key Confirmation");
    private static IEnumerable<TestCaseData> FfcZzFiles() => Files("FFC", "Test of 800-56A excluding KDF");
    private static IEnumerable<TestCaseData> FfcKdfFiles() => Files("FFC", "No Key Confirmation");
    private static IEnumerable<TestCaseData> FfcKcFiles() => Files("FFC", "Key Confirmation");

    private static IEnumerable<TestCaseData> Files(string family, string stage)
    {
        string root = TestPaths.Vectors("SP800-56A", $"KASTestVectors{family}2016", stage);
        return Directory.EnumerateFiles(root, "*.fax", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.Ordinal)
            .Select(path => new TestCaseData(Path.GetRelativePath(TestPaths.Vectors("SP800-56A"), path))
                .SetName($"{family}_{Path.GetFileNameWithoutExtension(path)}"));
    }

    private static void Run(string relativePath) =>
        Cavp.RunAll(KasVector.Read(TestPaths.Vectors("SP800-56A", relativePath)), Validate, v => v.ToString());

    internal static void Validate(KasVector v)
    {
        byte[] z;
        try
        {
            z = KasRunner.ComputeZ(v);
        }
        catch (KeyRejectedException rejected) when (v.Rejection is { } expected)
        {
            Assert.That((rejected.Party, rejected.Role), Is.EqualTo((expected.Party, expected.Role)), "The wrong key was rejected.");
            Assert.That(expected.Failures, Does.Contain(rejected.Failure), "The key was rejected for the wrong reason.");
            return;
        }

        Assert.That(v.Rejection, Is.Null, $"Expected '{v.Description}' to be rejected, but key agreement completed.");
        if (v.Effect == KasEffect.ZChanged) { Assert.That(z, Is.Not.EqualTo(v.Hex("Z"))); return; }
        Assert.That(z, Is.EqualTo(v.Hex("Z")), "Z");
        if (v.Stage == KasStage.Zz) return;

        byte[] expectedDkm = v.Hex("DKM");
        byte[] dkm = Sp80056C.OneStep(z, OneStepFunction.HashFunction(Hash(v.Hash)), v.Hex("OI"),
            BitLength.FromBytes(expectedDkm.Length), SecurityStrength.Bits112);
        if (v.Effect is KasEffect.DkmChanged or KasEffect.OiChanged) { Assert.That(dkm, Is.Not.EqualTo(expectedDkm)); return; }
        Assert.That(dkm, Is.EqualTo(expectedDkm), "DKM");
        if (v.Stage == KasStage.Kdf) return;

        byte[] cavsTag = v.Hex("CAVSTag");
        byte[] macData = v.Hex("MacData");
        var context = KcContext(v);
        if (v.Effect == KasEffect.MacDataChanged)
        {
            Assert.That(context.EncodeMacData(), Is.Not.EqualTo(macData));
            Assert.That(Tag(v, dkm, macData, cavsTag.Length), Is.EqualTo(cavsTag), "CAVSTag authenticates the reference MacData.");
            Assert.That(Tag(v, dkm, context.EncodeMacData(), cavsTag.Length), Is.Not.EqualTo(cavsTag));
            return;
        }

        Assert.That(context.EncodeMacData(), Is.EqualTo(macData), "MacData");
        bool verified = Verify(v, dkm, context, cavsTag);
        Assert.That(verified, Is.EqualTo(v.Effect != KasEffect.TagChanged), "Tag verification");
    }

    private static NistHashAlgorithm Hash(string name) => name switch
    {
        "SHA224" => NistHashAlgorithm.Sha224,
        "SHA256" => NistHashAlgorithm.Sha256,
        "SHA384" => NistHashAlgorithm.Sha384,
        "SHA512" => NistHashAlgorithm.Sha512,
        _ => throw new InvalidDataException($"Unknown hash '{name}'.")
    };

    private static KeyConfirmationMac? ProductionMac(KasVector v) => v.MacVariant!.Split(' ') switch
    {
        ["CMAC", var aes] => KeyConfirmationMac.AesCmac(int.Parse(aes[3..])),
        ["HMAC", var sha] => KeyConfirmationMac.Hmac(Hash(sha)),
        ["CCM", _] => null, // AES-CCM was in the 2016 corpus but is not a Rev. 3 key-confirmation MAC.
        _ => throw new InvalidDataException($"Unknown MAC '{v.MacVariant}'.")
    };

    private static bool Verify(KasVector v, byte[] macKey, KeyConfirmationContext context, byte[] tag) =>
        ProductionMac(v) is { } mac
            ? KeyConfirmation.VerifyTag(tag, macKey, context, mac, BitLength.FromBytes(tag.Length), SecurityStrength.Bits112)
            : Tag(v, macKey, context.EncodeMacData(), tag.Length).AsSpan().SequenceEqual(tag);

    /// <summary>A tag over arbitrary MacData, for checking the corpus's own reference tags.</summary>
    private static byte[] Tag(KasVector v, byte[] macKey, byte[] macData, int tagBytes)
    {
        if (ProductionMac(v) is { Prf: { } prf })
        {
            var mac = prf.IsCmac ? (Org.BouncyCastle.Crypto.IMac)new Org.BouncyCastle.Crypto.Macs.CMac(new AesEngine())
                : new Org.BouncyCastle.Crypto.Macs.HMac(prf.Hash switch
                {
                    NistHashAlgorithm.Sha224 => new Org.BouncyCastle.Crypto.Digests.Sha224Digest(),
                    NistHashAlgorithm.Sha256 => new Org.BouncyCastle.Crypto.Digests.Sha256Digest(),
                    NistHashAlgorithm.Sha384 => new Org.BouncyCastle.Crypto.Digests.Sha384Digest(),
                    _ => new Org.BouncyCastle.Crypto.Digests.Sha512Digest()
                });
            mac.Init(new KeyParameter(macKey));
            mac.BlockUpdate(macData, 0, macData.Length);
            var full = new byte[mac.GetMacSize()];
            mac.DoFinal(full, 0);
            return full[..tagBytes];
        }

        var ccm = new CcmBlockCipher(new AesEngine());
        ccm.Init(true, new AeadParameters(new KeyParameter(macKey), tagBytes * 8, v.Hex("CCMNonce"), macData));
        var output = new byte[ccm.GetOutputSize(0)];
        return output[..ccm.DoFinal(output, 0)];
    }

    /// <summary>MacData inputs: IUTid a1b2c3d4e5, CAVSid "CAVSid"; U is the initiator.</summary>
    private static KeyConfirmationContext KcContext(KasVector v)
    {
        string name = Path.GetFileNameWithoutExtension(v.Record.File);
        bool iutIsU = v.IutIsInitiator;
        bool iutProvides = name.Contains("_prov_", StringComparison.Ordinal);
        byte[] iutId = Convert.FromHexString("a1b2c3d4e5");
        byte[] cavsId = "CAVSid"u8.ToArray();
        byte[] iutEphemeral = EphemeralData(v, "IUT");
        byte[] cavsEphemeral = EphemeralData(v, "CAVS");
        return new KeyConfirmationContext(
            name.Contains("_blat", StringComparison.Ordinal) ? KeyConfirmationMode.Bilateral : KeyConfirmationMode.Unilateral,
            iutProvides == iutIsU ? Party.U : Party.V,
            iutIsU ? iutId : cavsId,
            iutIsU ? cavsId : iutId,
            iutIsU ? iutEphemeral : cavsEphemeral,
            iutIsU ? cavsEphemeral : iutEphemeral);
    }

    /// <summary>A party's ephemeral public key, or the nonce that replaces it, or nothing.</summary>
    private static byte[] EphemeralData(KasVector v, string party)
    {
        // An ECC ephemeral key enters MacData as X || Y at the field width. The corpus pads some
        // coordinates (all of P-521's) with extra zero bytes, so reuse the fixed-width encoding.
        if (v.Field($"Qe{party}x") is not null)
            return KasRunner.Point(KasRunner.Domain(v), v, $"Qe{party}")[1..];
        foreach (string name in new[] { $"Yephem{party}", $"NonceEphem{party}", $"NonceDKM{party}" })
            if (v.Field(name) is { } value)
                return Convert.FromHexString(value);
        return [];
    }
}

/// <summary>Fast-lane smoke test: the first passing vector of each shard runs through the strict harness.</summary>
[TestFixture]
public class KasCavpSmokeTests
{
    [TestCase("ECC", "Test of 800-56A excluding KDF")]
    [TestCase("ECC", "No Key Confirmation")]
    [TestCase("ECC", "Key Confirmation")]
    [TestCase("FFC", "Test of 800-56A excluding KDF")]
    [TestCase("FFC", "No Key Confirmation")]
    [TestCase("FFC", "Key Confirmation")]
    public void FirstVectorsOfEachShardPass(string family, string stage)
    {
        string file = Directory.EnumerateFiles(TestPaths.Vectors("SP800-56A", $"KASTestVectors{family}2016", stage), "*.fax", SearchOption.AllDirectories)
            .Order(StringComparer.Ordinal).First();
        foreach (KasVector v in KasVector.Read(file).Take(25))
            KasCavpTests.Validate(v);
    }

    // Regression: a harness error (here, a missing key field) used to satisfy "key rejected" vectors.
    [TestCase("ECC")]
    [TestCase("FFC")]
    public void AHarnessErrorNeverCountsAsAnExpectedRejection(string family)
    {
        string file = Directory.EnumerateFiles(TestPaths.Vectors("SP800-56A", $"KASTestVectors{family}2016", "Test of 800-56A excluding KDF"), "*.fax", SearchOption.AllDirectories)
            .Order(StringComparer.Ordinal).First();
        KasVector rejected = KasVector.Read(file).First(v => v.Rejection is { Party: "CAVS" });
        string field = family == "ECC" ? (rejected.Rejection!.Role == "static" ? "QsCAVSx" : "QeCAVSx") : (rejected.Rejection!.Role == "static" ? "YstatCAVS" : "YephemCAVS");
        var fields = rejected.Record.Fields.Where(f => f.Key != field).ToDictionary(f => f.Key, f => f.Value);
        KasVector broken = rejected with { Record = rejected.Record with { Fields = fields } };

        Assert.That(() => KasCavpTests.Validate(rejected), Throws.Nothing);
        Assert.That(() => KasCavpTests.Validate(broken), Throws.InstanceOf<InvalidDataException>());
    }
}
