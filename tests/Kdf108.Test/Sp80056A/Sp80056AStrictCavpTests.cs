// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

        if (vector.ResultEffect == CavpResultEffect.KeyRejected)
            Assert.Fail($"Vector {vector.Count} expected key rejection but key agreement completed.");
        if (vector.ResultEffect == CavpResultEffect.ZMismatch)
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
        if (vector.ResultEffect is CavpResultEffect.DkmMismatch or CavpResultEffect.OiMismatch)
        {
            Assert.That(dkm, Is.Not.EqualTo(vector.DKM));
            return;
        }
        Assert.That(dkm, Is.EqualTo(vector.DKM));
        if (vector.Source.Stage != CavpStage.KeyConfirmation) return;

        Assert.That(vector.MacData, Is.Not.Null);
        Assert.That(vector.CAVSTag, Is.Not.Null);
        byte[] encoded = CavpKeyConfirmation.EncodeMacData(vector);
        if (vector.ResultEffect == CavpResultEffect.MacDataMismatch)
        {
            Assert.That(encoded, Is.Not.EqualTo(vector.MacData));
            Assert.That(CavpKeyConfirmation.GenerateTagOverEncodedData(vector, dkm, vector.MacData!),
                Is.EqualTo(vector.CAVSTag), "CAVSTag authenticates the unmodified reference MacData.");
            Assert.That(CavpKeyConfirmation.GenerateProductionTag(vector, dkm),
                Is.Not.EqualTo(vector.CAVSTag), "The changed IUT MacData must not reproduce the reference tag.");
            return;
        }
        Assert.That(encoded, Is.EqualTo(vector.MacData));
        byte[] tag = CavpKeyConfirmation.GenerateProductionTag(vector, dkm);
        if (vector.ResultEffect == CavpResultEffect.TagMismatch)
        {
            Assert.That(tag, Is.Not.EqualTo(vector.CAVSTag),
                "The corpus tag marked as changed must differ from the production tag.");
            Assert.That(CavpKeyConfirmation.VerifyProductionTag(vector, dkm, vector.CAVSTag!), Is.False,
                "A changed CAVP tag must fail key-confirmation verification.");
        }
        else
        {
            Assert.That(tag, Is.EqualTo(vector.CAVSTag));
            Assert.That(CavpKeyConfirmation.VerifyProductionTag(vector, dkm, vector.CAVSTag!), Is.True);
        }
    }

    private static bool IsExpectedKeyRejection(CavpTestVector vector, Exception exception) =>
        vector.ResultEffect == CavpResultEffect.KeyRejected &&
        exception is ArgumentException or InvalidOperationException or
            Kdf108.Exceptions.CryptographicException or Sp80056AKeyAgreementException;

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
