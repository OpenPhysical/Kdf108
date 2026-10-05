using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Kdf108.Test.Support;

namespace Kdf108.Test.Nist800108;

/// <summary>
/// Executes every conforming vector in the pinned NIST CAVP SP 800-108 corpus through
/// <see cref="Sp800108.Derive(ReadOnlySpan{byte}, Prf, KeyExpansion, BitLength, Microsoft.Extensions.Logging.ILogger?)"/>.
/// TDEA vectors are counted but not run: SP 800-131A disallows TDEA KDFs and the API cannot select one.
/// </summary>
[TestFixture]
[Category("CAVP")]
[Category("CAVP-SP800-108")]
[Parallelizable(ParallelScope.All)]
public class Sp800108CavpTests
{
    private static IEnumerable<TestCaseData> Files() =>
        Directory.EnumerateFiles(TestPaths.Vectors("SP800-108"), "*.rsp")
            .OrderBy(path => path, StringComparer.Ordinal)
            .Select(path => new TestCaseData(Path.GetFileName(path)).SetName(Path.GetFileNameWithoutExtension(path)));

    [TestCaseSource(nameof(Files))]
    public void EveryVectorMatches(string fileName)
    {
        var records = RspReader.Read(TestPaths.Vectors("SP800-108", fileName)).ToList();
        var legacy = records.Where(r => r.Header("PRF") is "CMAC_TDES2" or "CMAC_TDES3").ToList();
        var conforming = records.Except(legacy).ToList();

        var expected = Cavp.ExpectedCorpusCounts(fileName);
        Assert.That((conforming.Count, legacy.Count), Is.EqualTo(expected), "Corpus classification drifted from the manifest.");

        KdfMode mode = fileName.StartsWith("KDFCTR", StringComparison.Ordinal) ? KdfMode.Counter
            : fileName.StartsWith("KDFFeedback", StringComparison.Ordinal) ? KdfMode.Feedback
            : KdfMode.DoublePipeline;

        Cavp.RunAll(conforming, record =>
        {
            byte[] actual = Sp800108.Derive(record.Hex("KI"), ParsePrf(record.Header("PRF")!),
                Expansion(mode, record), BitLength.Create(long.Parse(record.Text("L"))));
            Assert.That(actual, Is.EqualTo(record.Hex("KO")));
        }, record => record.ToString());
    }

    internal static Prf ParsePrf(string name) => name switch
    {
        "CMAC_AES128" => Prf.AesCmac(128),
        "CMAC_AES192" => Prf.AesCmac(192),
        "CMAC_AES256" => Prf.AesCmac(256),
        "HMAC_SHA1" => Prf.Hmac(NistHashAlgorithm.Sha1),
        "HMAC_SHA224" => Prf.Hmac(NistHashAlgorithm.Sha224),
        "HMAC_SHA256" => Prf.Hmac(NistHashAlgorithm.Sha256),
        "HMAC_SHA384" => Prf.Hmac(NistHashAlgorithm.Sha384),
        "HMAC_SHA512" => Prf.Hmac(NistHashAlgorithm.Sha512),
        _ => throw new InvalidDataException($"Unknown PRF '{name}'.")
    };

    private static KeyExpansion Expansion(KdfMode mode, RspRecord record)
    {
        string? location = record.Header("CTRLOCATION");
        int r = record.Header("RLEN") is { } rlen ? int.Parse(rlen.Split('_')[0]) : 32;
        byte[] Fixed() => record.Hex("FixedInputData");

        return (mode, location) switch
        {
            (KdfMode.Counter, "BEFORE_FIXED") => KeyExpansion.Counter(Fixed(), r, CounterPosition.BeforeFixedInput),
            (KdfMode.Counter, "AFTER_FIXED") => KeyExpansion.Counter(Fixed(), r, CounterPosition.AfterFixedInput),
            (KdfMode.Counter, "MIDDLE_FIXED") => KeyExpansion.CounterInMiddle(record.Hex("DataBeforeCtrData"), record.Hex("DataAfterCtrData"), r),
            (KdfMode.Feedback, _) => KeyExpansion.Feedback(Fixed(), record.Hex("IV"), location is not null, r, Position(location)),
            (KdfMode.DoublePipeline, _) => KeyExpansion.DoublePipeline(Fixed(), location is not null, r, Position(location)),
            _ => throw new InvalidDataException($"{record}: unknown counter location '{location}'.")
        };
    }

    private static IterationCounterPosition Position(string? location) => location switch
    {
        null or "AFTER_ITER" => IterationCounterPosition.AfterIteration,
        "BEFORE_ITER" => IterationCounterPosition.BeforeIteration,
        "AFTER_FIXED" => IterationCounterPosition.AfterFixedInput,
        _ => throw new InvalidDataException($"Unknown counter location '{location}'.")
    };
}
