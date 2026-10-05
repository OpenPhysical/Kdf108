using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Kdf108.Test.Support;
using Org.BouncyCastle.Math;

namespace Kdf108.Test.Nist80056A;

[TestFixture]
[Parallelizable(ParallelScope.All)]
public class KeyAgreementTests
{
    private static IEnumerable<EcCurve> Curves() => Enum.GetValues<EcCurve>();

    [TestCaseSource(nameof(Curves))]
    public void EverySchemeAgreesOnEveryCurve(EcCurve curve)
    {
        var d = EcDomain.Named(curve);
        var uS = EcStaticKeyPair.Generate(d);
        var uE = EcEphemeralKeyPair.Generate(d);
        var vS = EcStaticKeyPair.Generate(d);
        var vE = EcEphemeralKeyPair.Generate(d);
        int z = (d.FieldBits + 7) / 8;

        AssertAgree(EcSchemes.Ephemeral(uE, vE.PublicKey), EcSchemes.Ephemeral(vE, uE.PublicKey), z);
        AssertAgree(EcSchemes.Static(uS, vS.PublicKey), EcSchemes.Static(vS, uS.PublicKey), z);
        AssertAgree(EcSchemes.OneFlowAsPartyU(uE, vS.PublicKey), EcSchemes.OneFlowAsPartyV(vS, uE.PublicKey), z);
        AssertAgree(EcSchemes.Hybrid(uS, uE, vS.PublicKey, vE.PublicKey), EcSchemes.Hybrid(vS, vE, uS.PublicKey, uE.PublicKey), 2 * z);
        AssertAgree(EcSchemes.HybridOneFlowAsPartyU(uS, uE, vS.PublicKey), EcSchemes.HybridOneFlowAsPartyV(vS, uS.PublicKey, uE.PublicKey), 2 * z);
        AssertAgree(EcSchemes.Mqv2(uS, uE, vS.PublicKey, vE.PublicKey), EcSchemes.Mqv2(vS, vE, uS.PublicKey, uE.PublicKey), z);
        AssertAgree(EcSchemes.Mqv1AsPartyU(uS, uE, vS.PublicKey), EcSchemes.Mqv1AsPartyV(vS, uS.PublicKey, uE.PublicKey), z);
    }

    [Test]
    public void EverySchemeAgreesInFfc()
    {
        var d = FfcDomain.Named(FfcSafePrimeGroup.Ffdhe2048);
        var uS = FfcStaticKeyPair.FromPrivate(d, [0x02]);
        var uE = FfcEphemeralKeyPair.FromPrivate(d, [0x03]);
        var vS = FfcStaticKeyPair.FromPrivate(d, [0x05]);
        var vE = FfcEphemeralKeyPair.FromPrivate(d, [0x07]);

        AssertAgree(FfcSchemes.Ephemeral(uE, vE.PublicKey), FfcSchemes.Ephemeral(vE, uE.PublicKey), 256);
        AssertAgree(FfcSchemes.Static(uS, vS.PublicKey), FfcSchemes.Static(vS, uS.PublicKey), 256);
        AssertAgree(FfcSchemes.OneFlowAsPartyU(uE, vS.PublicKey), FfcSchemes.OneFlowAsPartyV(vS, uE.PublicKey), 256);
        AssertAgree(FfcSchemes.Hybrid(uS, uE, vS.PublicKey, vE.PublicKey), FfcSchemes.Hybrid(vS, vE, uS.PublicKey, uE.PublicKey), 512);
        AssertAgree(FfcSchemes.HybridOneFlowAsPartyU(uS, uE, vS.PublicKey), FfcSchemes.HybridOneFlowAsPartyV(vS, uS.PublicKey, uE.PublicKey), 512);
        AssertAgree(FfcSchemes.Mqv2(uS, uE, vS.PublicKey, vE.PublicKey), FfcSchemes.Mqv2(vS, vE, uS.PublicKey, uE.PublicKey), 256);
        AssertAgree(FfcSchemes.Mqv1AsPartyU(uS, uE, vS.PublicKey), FfcSchemes.Mqv1AsPartyV(vS, uS.PublicKey, uE.PublicKey), 256);
    }

    // Regression: MQV used to check every domain except the local ephemeral key's.
    [Test]
    public void MqvRejectsALocalEphemeralKeyFromAnotherDomain()
    {
        var d = FfcDomain.Named(FfcSafePrimeGroup.Ffdhe2048);
        var other = FfcDomain.Named(FfcSafePrimeGroup.Modp2048);
        var uS = FfcStaticKeyPair.Generate(d);
        var vS = FfcStaticKeyPair.Generate(d);
        var vE = FfcEphemeralKeyPair.Generate(d);
        var foreign = FfcEphemeralKeyPair.Generate(other);

        Assert.That(Assert.Throws<InvalidKeyException>(() => FfcSchemes.Mqv2(uS, foreign, vS.PublicKey, vE.PublicKey))!.Failure, Is.EqualTo(KeyFailure.DomainMismatch));
        Assert.That(Assert.Throws<InvalidKeyException>(() => FfcSchemes.Mqv1AsPartyU(uS, foreign, vS.PublicKey))!.Failure, Is.EqualTo(KeyFailure.DomainMismatch));
        var ec = EcDomain.Named(EcCurve.P256);
        Assert.Throws<InvalidKeyException>(() => EcSchemes.Mqv2(EcStaticKeyPair.Generate(ec), EcEphemeralKeyPair.Generate(EcDomain.Named(EcCurve.P384)),
            EcStaticKeyPair.Generate(ec).PublicKey, EcEphemeralKeyPair.Generate(ec).PublicKey));
    }

    // Regression: points with x = 0 or y = 0 are valid keys (§5.6.2.3.3 does not exclude them) and used to be rejected.
    [Test]
    public void APointWithXZeroIsAValidPublicKey()
    {
        var d = EcDomain.Named(EcCurve.P256);
        var curve = d.Parameters.Curve;
        var y = curve.B.Sqrt();
        Assert.That(y, Is.Not.Null, "b is a quadratic residue on P-256");
        var point = curve.CreatePoint(BigInteger.Zero, y!.ToBigInteger());
        Assert.That(() => EcStaticPublicKey.Import(d, d.Encode(point)), Throws.Nothing);
    }

    [Test]
    public void InvalidEcPublicKeysAreRejected()
    {
        var d = EcDomain.Named(EcCurve.P256);
        byte[] valid = EcStaticKeyPair.Generate(d).PublicKey.Export();
        byte[] offCurve = (byte[])valid.Clone();
        offCurve[^1] ^= 1;
        byte[] compressed = valid[..33];
        compressed[0] = 0x02;
        byte[] xTooLarge = (byte[])valid.Clone();
        xTooLarge.AsSpan(1, 32).Fill(0xFF);

        foreach (byte[] bad in new[] { offCurve, compressed, xTooLarge, new byte[65], valid[..64] })
            Assert.That(Assert.Throws<InvalidKeyException>(() => EcStaticPublicKey.Import(d, bad))!.Failure, Is.EqualTo(KeyFailure.InvalidPublicKey));
    }

    [Test]
    public void BinaryCurveKeysOutsideTheSubgroupAreRejected()
    {
        // On K-233 (cofactor 4) a point of order 2 lies on the curve but outside the order-n subgroup.
        var d = EcDomain.Named(EcCurve.K233);
        var curve = d.Parameters.Curve;
        var x = curve.FromBigInteger(BigInteger.Zero);
        var orderTwo = curve.CreatePoint(BigInteger.Zero, curve.B.Sqrt().ToBigInteger());
        Assert.That(orderTwo.Twice().IsInfinity, Is.True);
        Assert.Throws<InvalidKeyException>(() => EcStaticPublicKey.Import(d, d.Encode(orderTwo)));
        _ = x;
    }

    [Test]
    public void PrivateKeysOutsideTheRangeAreRejected()
    {
        var ec = EcDomain.Named(EcCurve.P256);
        Assert.Throws<InvalidKeyException>(() => EcStaticKeyPair.FromPrivate(ec, [0]));
        Assert.Throws<InvalidKeyException>(() => EcStaticKeyPair.FromPrivate(ec, ec.Parameters.N.ToByteArrayUnsigned()));
        var ffc = FfcDomain.Named(FfcSafePrimeGroup.Modp2048);
        Assert.Throws<InvalidKeyException>(() => FfcStaticKeyPair.FromPrivate(ffc, [0]));
        Assert.Throws<InvalidKeyException>(() => FfcStaticKeyPair.FromPrivate(ffc, ffc.Q.ToByteArrayUnsigned()));
    }

    [Test]
    public void ImportedKeyPairsMustCorrespond()
    {
        var ec = EcDomain.Named(EcCurve.P256);
        var a = EcStaticKeyPair.Generate(ec);
        var b = EcStaticKeyPair.Generate(ec);
        Assert.That(() => EcStaticKeyPair.Import(ec, a.ExportPrivate(), a.PublicKey.Export()), Throws.Nothing);
        Assert.That(Assert.Throws<InvalidKeyException>(() => EcStaticKeyPair.Import(ec, a.ExportPrivate(), b.PublicKey.Export()))!.Failure, Is.EqualTo(KeyFailure.KeyPairMismatch));

        var ffc = FfcDomain.Named(FfcSafePrimeGroup.Ffdhe2048);
        var f = FfcEphemeralKeyPair.Generate(ffc);
        var g = FfcEphemeralKeyPair.Generate(ffc);
        Assert.That(() => FfcEphemeralKeyPair.Import(ffc, f.ExportPrivate(), f.PublicKey.Export()), Throws.Nothing);
        Assert.That(Assert.Throws<InvalidKeyException>(() => FfcEphemeralKeyPair.Import(ffc, f.ExportPrivate(), g.PublicKey.Export()))!.Failure, Is.EqualTo(KeyFailure.KeyPairMismatch));
    }

    [Test]
    public void FfcPublicKeysOutsideTheRangeOrSubgroupAreRejected()
    {
        var d = FfcDomain.Named(FfcSafePrimeGroup.Modp2048);
        foreach (BigInteger y in new[] { BigInteger.One, d.P.Subtract(BigInteger.One), d.P })
            Assert.Throws<InvalidKeyException>(() => FfcStaticPublicKey.Import(d, d.Encode(y)));
    }

    [TestCase(0)]
    [TestCase(1)]
    public void ForbiddenFfcSharedSecretsAreRejected(int remoteY)
    {
        var d = FfcDomain.Named(FfcSafePrimeGroup.Modp2048);
        Assert.Throws<KeyAgreementException>(() => FfcPrimitives.Dh(d, BigInteger.Two, BigInteger.ValueOf(remoteY)));
        Assert.Throws<KeyAgreementException>(() => FfcPrimitives.Dh(d, BigInteger.One, d.P.Subtract(BigInteger.One)));
    }

    [Test]
    public void Fips186TrustedAuthorityImportsCavpParameters()
    {
        var header = RspReader.Read(TestPaths.Vectors("SP800-56A", "KASTestVectorsFFC2016", "Key Confirmation", "FFC MQV1 Scheme",
            "KASValidityTest_FFCMQV1_KDFConcat_KC_resp_prov_ulat.fax")).First();
        var domain = FfcDomain.ImportFips186(Convert.FromHexString(header.Header("P")!), Convert.FromHexString(header.Header("Q")!),
            Convert.FromHexString(header.Header("G")!), FfcDomainAssurance.TrustedAuthority("NIST CAVP"));
        Assert.That(domain.Group, Is.Null);
        Assert.That(domain.ModulusBits, Is.EqualTo(2048));
    }

    // NIST CAVP FIPS 186-3 DSA PQGVer (retained by FIPS 186-4 A.1.1.3): L=2048, N=224, SHA-224, counter 307, Result=P.
    [Test]
    public void Fips186EvidenceReplaysTheNistValidationVector()
    {
        var (p, q, g, seed) = NistProbablePrimeVector();
        var domain = FfcDomain.ImportFips186(p, q, g, FfcDomainAssurance.Fips186Evidence(seed, 307, NistHashAlgorithm.Sha224));
        Assert.That(domain.Assurance!.Counter, Is.EqualTo(307));
    }

    [Test]
    public void Fips186EvidenceRejectsTheWrongCounterHashOrSeedAndABadGenerator()
    {
        var (p, q, g, seed) = NistProbablePrimeVector();
        Assert.Throws<InvalidKeyException>(() => FfcDomain.ImportFips186(p, q, g, FfcDomainAssurance.Fips186Evidence(seed, 306, NistHashAlgorithm.Sha224)));
        Assert.Throws<InvalidKeyException>(() => FfcDomain.ImportFips186(p, q, g, FfcDomainAssurance.Fips186Evidence(seed, 307, NistHashAlgorithm.Sha256)));
        byte[] badSeed = (byte[])seed.Clone();
        badSeed[0] ^= 1;
        Assert.Throws<InvalidKeyException>(() => FfcDomain.ImportFips186(p, q, g, FfcDomainAssurance.Fips186Evidence(badSeed, 307, NistHashAlgorithm.Sha224)));
        Assert.Throws<InvalidKeyException>(() => FfcDomain.ImportFips186(p, q, [1], FfcDomainAssurance.TrustedAuthority("NIST CAVP")));
        Assert.Throws<InvalidKeyException>(() => FfcDomainAssurance.Fips186Evidence(seed, 307, NistHashAlgorithm.Sha1));
    }

    private static void AssertAgree(byte[] u, byte[] v, int expectedLength)
    {
        Assert.That(u, Is.EqualTo(v));
        Assert.That(u, Has.Length.EqualTo(expectedLength));
    }

    private static (byte[] P, byte[] Q, byte[] G, byte[] Seed) NistProbablePrimeVector()
    {
        byte[] p = Convert.FromHexString(
            "B0C026CE57C43F982DECD609FBEFFA9F07B14182930D04AE3899D5C2A915363965C959DEBA558BBA852443F5009C40BCBF3A77FCCD2A4018F86D1246FCE29E89EE0D0F0441B60E2CE21CCC5D64E783705838C55CC9CC1633D6FE40C847E680D18BAB9D1B4E76555203B5690DA2114A26D65C6AC8DE5FD52C4B9FED9423DD0A3D5B7F3E01C741DF99D9C10ED314F42C4DA287A9B0A2BC2374C93F9891C720B3B092D8180DCB61CC70CB6B4425286AAD77C82EB1751207EE06275AFAE4B243442B3A0DAF1C8596539B3B1557AAC13B2CDA6BF6723D1A651EB57091BFE71501013BA9AE4DA8C5B01553457B373BD5B5102B27632F28A2D71437EE274ED3EC9578DB");
        byte[] q = Convert.FromHexString("A09BBC32691F44132A667220CCF5EBFA77BA15016E1F993A0CB74691");
        var pValue = new BigInteger(1, p);
        byte[] g = BigInteger.Two.ModPow(pValue.Subtract(BigInteger.One).Divide(new BigInteger(1, q)), pValue).ToByteArrayUnsigned();
        return (p, q, g, Convert.FromHexString("3068DDE74863F18A3C6E5CAF244DF178C697A4B6AA087226C1ABE4AB"));
    }
}
