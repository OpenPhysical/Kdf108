// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Kdf108.Test.Sp80056A;

[TestFixture]
[Category("Unit")]
public class CavpTestVectorParserTests
{
    private static readonly IReadOnlyDictionary<(CavpFamily, CavpStage), int> ExpectedCounts =
        new Dictionary<(CavpFamily, CavpStage), int>
        {
            [(CavpFamily.Ecc, CavpStage.Zz)] = 1680,
            [(CavpFamily.Ecc, CavpStage.KdfNoKeyConfirmation)] = 4140,
            [(CavpFamily.Ecc, CavpStage.KeyConfirmation)] = 90240,
            [(CavpFamily.Ffc, CavpStage.Zz)] = 672,
            [(CavpFamily.Ffc, CavpStage.KdfNoKeyConfirmation)] = 2352,
            [(CavpFamily.Ffc, CavpStage.KeyConfirmation)] = 62352
        };

    [Test]
    public void BundledCorpora_HaveExactDisjointShardCountsAndStrictResults()
    {
        var counts = new Dictionary<(CavpFamily, CavpStage), int>();
        var seen = new HashSet<string>(System.StringComparer.Ordinal);

        foreach (string file in Directory.EnumerateFiles(GetVectorRoot(), "*.fax", SearchOption.AllDirectories))
        {
            foreach (CavpTestVector vector in CavpTestVectorParser.ParseFile(file))
            {
                var shard = (vector.Source.Family, vector.Source.Stage);
                counts[shard] = counts.GetValueOrDefault(shard) + 1;
                string identity = $"{file}|{vector.ParameterSet}|{vector.Hash}|{vector.MacVariant}|{vector.Count}";
                Assert.That(seen.Add(identity), Is.True, $"Duplicate vector identity: {identity}");
                Assert.That(vector.ResultCode, vector.ExpectPass ? Is.AnyOf(0, 10, 11, 13, 14) : Is.InRange(1, 12));
                if (vector.Source.Family == CavpFamily.Ffc)
                    Assert.That(vector.Fields.Keys, Does.Contain("P").And.Contain("Q").And.Contain("G"));
            }
        }

        Assert.That(counts, Is.EquivalentTo(ExpectedCounts));
        Assert.That(counts.Values.Sum(), Is.EqualTo(161436));
    }

    [TestCase("CCM ")]
    [TestCase("CMAC ")]
    [TestCase("HMAC ")]
    public void PositiveKeyConfirmationVector_EncodedMacDataAndTagMatch(string variantPrefix)
    {
        CavpTestVector vector = Directory.EnumerateFiles(
                Path.Combine(GetVectorRoot(), "KASTestVectorsECC2016", "Key Confirmation"),
                "*.fax", SearchOption.AllDirectories)
            .SelectMany(CavpTestVectorParser.ParseFile)
            .First(candidate => candidate.ExpectPass &&
                candidate.MacVariant?.StartsWith(variantPrefix, System.StringComparison.Ordinal) == true);

        Assert.That(CavpKeyConfirmation.EncodeMacData(vector), Is.EqualTo(vector.MacData));
        Assert.That(CavpKeyConfirmation.GenerateProductionTag(vector, vector.DKM!), Is.EqualTo(vector.CAVSTag));
    }

    [TestCase(CavpFamily.Ecc, CavpStage.Zz)]
    [TestCase(CavpFamily.Ecc, CavpStage.KdfNoKeyConfirmation)]
    [TestCase(CavpFamily.Ecc, CavpStage.KeyConfirmation)]
    [TestCase(CavpFamily.Ffc, CavpStage.Zz)]
    [TestCase(CavpFamily.Ffc, CavpStage.KdfNoKeyConfirmation)]
    [TestCase(CavpFamily.Ffc, CavpStage.KeyConfirmation)]
    public void RepresentativePositiveVector_PassesStrictProductionPath(CavpFamily family, CavpStage stage)
    {
        string familyDirectory = family == CavpFamily.Ecc ? "KASTestVectorsECC2016" : "KASTestVectorsFFC2016";
        CavpTestVector vector = Directory.EnumerateFiles(
                Path.Combine(GetVectorRoot(), familyDirectory), "*.fax", SearchOption.AllDirectories)
            .SelectMany(CavpTestVectorParser.ParseFile)
            .First(candidate => candidate.Source.Stage == stage && candidate.ExpectPass);

        Sp80056AStrictCavpTests.Validate(vector);
    }

    private static string GetVectorRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !directory.GetFiles("Kdf108.Test.csproj").Any())
            directory = directory.Parent;
        if (directory is null) throw new DirectoryNotFoundException("Could not locate the test project.");
        return Path.Combine(directory.FullName, "res", "vectors", "SP800-56A");
    }
}
