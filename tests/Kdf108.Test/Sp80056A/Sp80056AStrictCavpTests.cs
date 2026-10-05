// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Kdf108.Domain.Sp80056A;
using Kdf108.Exceptions;

namespace Kdf108.Test.Sp80056A;

[TestFixture]
[Category("LongRunning")]
[Parallelizable(ParallelScope.All)]
public class Sp80056AStrictCavpTests
{
    [TestCaseSource(nameof(EccZz))]
    [Category("CAVP-SP800-56A-ECC-ZZ")]
    public void EccZzVector(CavpTestVector vector) => Validate(vector);

    [TestCaseSource(nameof(EccKdf))]
    [Category("CAVP-SP800-56A-ECC-KDF")]
    public void EccKdfVector(CavpTestVector vector) => Validate(vector);

    [TestCaseSource(nameof(EccKc))]
    [Category("CAVP-SP800-56A-ECC-KC")]
    public void EccKeyConfirmationVector(CavpTestVector vector) => Validate(vector);

    [TestCaseSource(nameof(FfcZz))]
    [Category("CAVP-SP800-56A-FFC-ZZ")]
    public void FfcZzVector(CavpTestVector vector) => Validate(vector);

    [TestCaseSource(nameof(FfcKdf))]
    [Category("CAVP-SP800-56A-FFC-KDF")]
    public void FfcKdfVector(CavpTestVector vector) => Validate(vector);

    [TestCaseSource(nameof(FfcKc))]
    [Category("CAVP-SP800-56A-FFC-KC")]
    public void FfcKeyConfirmationVector(CavpTestVector vector) => Validate(vector);

    private static IEnumerable<TestCaseData> EccZz() => Cases(CavpFamily.Ecc, CavpStage.Zz);
    private static IEnumerable<TestCaseData> EccKdf() => Cases(CavpFamily.Ecc, CavpStage.KdfNoKeyConfirmation);
    private static IEnumerable<TestCaseData> EccKc() => Cases(CavpFamily.Ecc, CavpStage.KeyConfirmation);
    private static IEnumerable<TestCaseData> FfcZz() => Cases(CavpFamily.Ffc, CavpStage.Zz);
    private static IEnumerable<TestCaseData> FfcKdf() => Cases(CavpFamily.Ffc, CavpStage.KdfNoKeyConfirmation);
    private static IEnumerable<TestCaseData> FfcKc() => Cases(CavpFamily.Ffc, CavpStage.KeyConfirmation);

    private static IEnumerable<TestCaseData> Cases(CavpFamily family, CavpStage stage)
    {
        string root = Path.Combine(GetVectorRoot(), family == CavpFamily.Ecc ? "KASTestVectorsECC2016" : "KASTestVectorsFFC2016");
        foreach (string file in Directory.EnumerateFiles(root, "*.fax", SearchOption.AllDirectories).OrderBy(x => x, StringComparer.Ordinal))
        foreach (CavpTestVector vector in CavpTestVectorParser.ParseFile(file))
        {
            if (vector.Source.Stage != stage) continue;
            string name = $"{family}_{stage}_{vector.Source.Scheme}_{Path.GetFileNameWithoutExtension(file)}_{vector.ParameterSet}_{vector.Hash}_{vector.MacVariant}_{vector.Count:D4}";
            yield return new TestCaseData(vector).SetName(Sanitize(name));
        }
    }

    internal static void Validate(CavpTestVector vector)
    {
        byte[] z;
        try
        {
            z = vector.Source.Family == CavpFamily.Ecc
                ? EccCavpRunner.ComputeZ(vector)
                : FfcCavpRunner.ComputeZ(vector);
        }
        catch (AssertionException) { throw; }
        catch (Exception ex) when (IsExpectedKeyRejection(vector, ex)) { return; }

        string description = vector.ErrorDescription ?? string.Empty;
        if (IsKeyMutation(description))
            Assert.Fail($"Vector {vector.Count} expected key rejection but key agreement completed.");
        if (description.Contains("Z changed", StringComparison.OrdinalIgnoreCase))
        {
            Assert.That(z, Is.Not.EqualTo(vector.Z));
            return;
        }
        Assert.That(z, Is.EqualTo(vector.Z));
        if (vector.Source.Stage == CavpStage.Zz) return;

        Assert.That(vector.OI, Is.Not.Null);
        Assert.That(vector.DKM, Is.Not.Null);
        Assert.That(vector.Hash, Is.Not.Null.And.Not.Empty);
        byte[] dkm = Sp80056AConcatKdf.DeriveKeyMaterial(z, vector.OI!, vector.DKM!.Length, vector.Hash!);
        if (description.Contains("DKM changed", StringComparison.OrdinalIgnoreCase) ||
            description.Contains("OI changed", StringComparison.OrdinalIgnoreCase))
        {
            Assert.That(dkm, Is.Not.EqualTo(vector.DKM));
            return;
        }
        Assert.That(dkm, Is.EqualTo(vector.DKM));
        if (vector.Source.Stage != CavpStage.KeyConfirmation) return;

        Assert.That(vector.MacData, Is.Not.Null);
        Assert.That(vector.CAVSTag, Is.Not.Null);
        byte[] encoded = CavpKeyConfirmation.EncodeMacData(vector);
        if (description.Contains("MACData changed", StringComparison.OrdinalIgnoreCase))
        {
            Assert.That(encoded, Is.Not.EqualTo(vector.MacData));
            Assert.That(CavpKeyConfirmation.GenerateTagOverEncodedData(vector, dkm, vector.MacData!),
                Is.Not.EqualTo(vector.CAVSTag));
            return;
        }
        Assert.That(encoded, Is.EqualTo(vector.MacData));
        byte[] tag = CavpKeyConfirmation.GenerateProductionTag(vector, dkm);
        Assert.That(tag, description.Contains("Tag changed", StringComparison.OrdinalIgnoreCase)
            ? Is.Not.EqualTo(vector.CAVSTag)
            : Is.EqualTo(vector.CAVSTag));
    }

    private static bool IsExpectedKeyRejection(CavpTestVector vector, Exception exception) =>
        IsKeyMutation(vector.ErrorDescription ?? string.Empty) &&
        exception is ArgumentException or System.Security.Cryptography.CryptographicException or InvalidOperationException or
            Kdf108.Exceptions.CryptographicException or Sp80056AKeyAgreementException;

    private static bool IsKeyMutation(string description) =>
        description.Contains("public key", StringComparison.OrdinalIgnoreCase) ||
        description.Contains("private key", StringComparison.OrdinalIgnoreCase) ||
        description.Contains("prikey", StringComparison.OrdinalIgnoreCase);

    private static string GetVectorRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !directory.GetFiles("Kdf108.Test.csproj").Any()) directory = directory.Parent;
        return directory is null
            ? throw new DirectoryNotFoundException("Could not locate the test project.")
            : Path.Combine(directory.FullName, "res", "vectors", "SP800-56A");
    }

    private static string Sanitize(string value) => value
        .Replace(' ', '_').Replace('/', '_').Replace('\\', '_').Replace('[', '_').Replace(']', '_');
}
