// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.IO;
using System.Linq;
using AwesomeAssertions;
using Kdf108.Domain.Sp80056A;
using Org.BouncyCastle.Math;

namespace Kdf108.Test.Sp80056A;

[TestFixture]
public class FfcKeyAgreementTests
{
    [Test]
    public void DiffieHellman_PartiesProduceSameFixedWidthSecret()
    {
        var domain = FfcDomain.Named(FfcSafePrimeGroup.Ffdhe2048);
        var partyU = FfcEphemeralKeyPair.FromPrivate(domain, new byte[] { 0x02 });
        var partyV = FfcEphemeralKeyPair.FromPrivate(domain, new byte[] { 0x03 });

        var uSecret = FfcKeyAgreement.DiffieHellman(partyU, partyV.PublicKey);
        var vSecret = FfcKeyAgreement.DiffieHellman(partyV, partyU.PublicKey);

        uSecret.Should().Equal(vSecret);
        uSecret.Should().HaveCount(256);
    }

    [Test]
    public void Mqv_PartiesProduceSameFixedWidthSecret()
    {
        var domain = FfcDomain.Named(FfcSafePrimeGroup.Ffdhe2048);
        var uStatic = FfcStaticKeyPair.FromPrivate(domain, new byte[] { 0x02 });
        var uEphemeral = FfcEphemeralKeyPair.FromPrivate(domain, new byte[] { 0x03 });
        var vStatic = FfcStaticKeyPair.FromPrivate(domain, new byte[] { 0x05 });
        var vEphemeral = FfcEphemeralKeyPair.FromPrivate(domain, new byte[] { 0x07 });

        var uSecret = FfcKeyAgreement.Mqv(uStatic, uEphemeral, vStatic.PublicKey, vEphemeral.PublicKey);
        var vSecret = FfcKeyAgreement.Mqv(vStatic, vEphemeral, uStatic.PublicKey, uEphemeral.PublicKey);

        uSecret.Should().Equal(vSecret);
        uSecret.Should().HaveCount(256);
    }

    [Test]
    public void Mqv1_PartiesProduceSameFixedWidthSecret()
    {
        var domain = FfcDomain.Named(FfcSafePrimeGroup.Ffdhe2048);
        var uStatic = FfcStaticKeyPair.FromPrivate(domain, new byte[] { 0x02 });
        var uEphemeral = FfcEphemeralKeyPair.FromPrivate(domain, new byte[] { 0x03 });
        var vStatic = FfcStaticKeyPair.FromPrivate(domain, new byte[] { 0x05 });

        var uSecret = FfcSchemes.Mqv1AsPartyU(uStatic, uEphemeral, vStatic.PublicKey);
        var vSecret = FfcSchemes.Mqv1AsPartyV(vStatic, uStatic.PublicKey, uEphemeral.PublicKey);

        uSecret.Should().Equal(vSecret);
        uSecret.Should().HaveCount(256);
    }

    [Test]
    public void DhHybridOneFlow_RolesProduceSameOrderedSecret()
    {
        var domain = FfcDomain.Named(FfcSafePrimeGroup.Ffdhe2048);
        var uStatic = FfcStaticKeyPair.FromPrivate(domain, new byte[] { 0x02 });
        var uEphemeral = FfcEphemeralKeyPair.FromPrivate(domain, new byte[] { 0x03 });
        var vStatic = FfcStaticKeyPair.FromPrivate(domain, new byte[] { 0x05 });

        var uSecret = FfcSchemes.DhHybridOneFlowAsPartyU(uStatic, uEphemeral, vStatic.PublicKey);
        var vSecret = FfcSchemes.DhHybridOneFlowAsPartyV(vStatic, uStatic.PublicKey, uEphemeral.PublicKey);

        uSecret.Should().Equal(vSecret);
        uSecret.Should().HaveCount(512);
    }

    [Test]
    public void ImportPublicKey_RejectsValueOutsideRequiredRange()
    {
        var domain = FfcDomain.Named(FfcSafePrimeGroup.Modp2048);

        Action act = () => FfcStaticPublicKey.Import(domain, new byte[] { 0x01 });

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Test]
    public void ImportFips186_RequiresAssuranceAndValidatesFbParameters()
    {
        var vectorPath = GetFfcVectorPath();
        var p = ReadParameter(vectorPath, "P");
        var q = ReadParameter(vectorPath, "Q");
        var g = ReadParameter(vectorPath, "G");

        var domain = FfcDomain.ImportFips186(
            p, q, g,
            FfcDomainAssurance.TrustedAuthority("NIST CAVP vector set"));

        domain.IsNamedSafePrimeGroup.Should().BeFalse();
        domain.ModulusBits.Should().Be(2048);
        domain.Assurance.Should().BeOfType<FfcDomainAssurance.TrustedThirdParty>();
    }

    [Test]
    public void ImportFips186_RejectsMissingAssurance()
    {
        Action act = () => FfcDomain.ImportFips186(
            new byte[] { 1 }, new byte[] { 1 }, new byte[] { 2 }, null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Test]
    public void ImportFips186_ReplaysNistProbablePrimeValidationVector()
    {
        // NIST CAVP FIPS 186-3 DSA PQGVer. FIPS 186-4 retains this A.1.1.3
        // validation method. L=2048, N=224, SHA-224, Result=P.
        var p = Convert.FromHexString(
            "B0C026CE57C43F982DECD609FBEFFA9F07B14182930D04AE3899D5C2A915363965C959DEBA558BBA852443F5009C40BCBF3A77FCCD2A4018F86D1246FCE29E89EE0D0F0441B60E2CE21CCC5D64E783705838C55CC9CC1633D6FE40C847E680D18BAB9D1B4E76555203B5690DA2114A26D65C6AC8DE5FD52C4B9FED9423DD0A3D5B7F3E01C741DF99D9C10ED314F42C4DA287A9B0A2BC2374C93F9891C720B3B092D8180DCB61CC70CB6B4425286AAD77C82EB1751207EE06275AFAE4B243442B3A0DAF1C8596539B3B1557AAC13B2CDA6BF6723D1A651EB57091BFE71501013BA9AE4DA8C5B01553457B373BD5B5102B27632F28A2D71437EE274ED3EC9578DB");
        var q = Convert.FromHexString("A09BBC32691F44132A667220CCF5EBFA77BA15016E1F993A0CB74691");
        var seed = Convert.FromHexString("3068DDE74863F18A3C6E5CAF244DF178C697A4B6AA087226C1ABE4AB");
        var pValue = new BigInteger(1, p);
        var qValue = new BigInteger(1, q);
        byte[] g = BigInteger.Two.ModPow(pValue.Subtract(BigInteger.One).Divide(qValue), pValue).ToByteArrayUnsigned();
        var assurance = FfcDomainAssurance.Fips186ProbablePrimeValidation(
            seed, 307, FfcDomainParameterHash.Sha224);

        var domain = FfcDomain.ImportFips186(p, q, g, assurance);

        domain.Assurance.Should().BeSameAs(assurance);
        var evidence = domain.Assurance.Should().BeOfType<FfcDomainAssurance.GeneratedOrValidated>().Subject;
        evidence.Hash.Should().Be(FfcDomainParameterHash.Sha224);
        evidence.Counter.Should().Be(307);
    }

    [TestCase(306, FfcDomainParameterHash.Sha224, "counter")]
    [TestCase(307, FfcDomainParameterHash.Sha256, "hash")]
    public void ImportFips186_RejectsMismatchedProbablePrimeEvidence(
        int counter,
        FfcDomainParameterHash hash,
        string _)
    {
        var (p, q, g, seed) = NistProbablePrimeVector();
        var assurance = FfcDomainAssurance.Fips186ProbablePrimeValidation(seed, counter, hash);

        Action act = () => FfcDomain.ImportFips186(p, q, g, assurance);

        act.Should().Throw<ArgumentException>();
    }

    [Test]
    public void ImportFips186_RejectsMismatchedSeedAndInvalidGenerator()
    {
        var (p, q, g, seed) = NistProbablePrimeVector();
        seed[0] ^= 1;
        var assurance = FfcDomainAssurance.Fips186ProbablePrimeValidation(
            seed, 307, FfcDomainParameterHash.Sha224);

        Action badSeed = () => FfcDomain.ImportFips186(p, q, g, assurance);
        Action badGenerator = () => FfcDomain.ImportFips186(
            p, q, new byte[] { 1 }, FfcDomainAssurance.TrustedAuthority("NIST CAVP"));

        badSeed.Should().Throw<ArgumentException>().WithMessage("*seed*hash*q*");
        badGenerator.Should().Throw<ArgumentException>().WithMessage("*subgroup*");
    }

    [TestCase("B-283")]
    [TestCase("K-409")]
    public void CurveRegistry_ContainsRemainingRev3BinaryCurves(string name)
    {
        CurveRegistry.IsSupported(name).Should().BeTrue();
    }

    private static string GetFfcVectorPath()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !directory.GetFiles("Kdf108.Test.csproj").Any())
            directory = directory.Parent;
        if (directory is null) throw new DirectoryNotFoundException("Could not locate the test project.");
        return Path.Combine(directory.FullName, "res", "vectors", "SP800-56A", "KASTestVectorsFFC2016",
            "Key Confirmation", "FFC MQV1 Scheme", "KASValidityTest_FFCMQV1_KDFConcat_KC_resp_prov_ulat.fax");
    }

    private static byte[] ReadParameter(string path, string name)
    {
        string prefix = name + " = ";
        string value = File.ReadLines(path).First(line => line.StartsWith(prefix, StringComparison.Ordinal))[prefix.Length..];
        return Convert.FromHexString(value);
    }

    private static (byte[] P, byte[] Q, byte[] G, byte[] Seed) NistProbablePrimeVector()
    {
        byte[] p = Convert.FromHexString(
            "B0C026CE57C43F982DECD609FBEFFA9F07B14182930D04AE3899D5C2A915363965C959DEBA558BBA852443F5009C40BCBF3A77FCCD2A4018F86D1246FCE29E89EE0D0F0441B60E2CE21CCC5D64E783705838C55CC9CC1633D6FE40C847E680D18BAB9D1B4E76555203B5690DA2114A26D65C6AC8DE5FD52C4B9FED9423DD0A3D5B7F3E01C741DF99D9C10ED314F42C4DA287A9B0A2BC2374C93F9891C720B3B092D8180DCB61CC70CB6B4425286AAD77C82EB1751207EE06275AFAE4B243442B3A0DAF1C8596539B3B1557AAC13B2CDA6BF6723D1A651EB57091BFE71501013BA9AE4DA8C5B01553457B373BD5B5102B27632F28A2D71437EE274ED3EC9578DB");
        byte[] q = Convert.FromHexString("A09BBC32691F44132A667220CCF5EBFA77BA15016E1F993A0CB74691");
        var pValue = new BigInteger(1, p);
        var qValue = new BigInteger(1, q);
        byte[] g = BigInteger.Two.ModPow(pValue.Subtract(BigInteger.One).Divide(qValue), pValue).ToByteArrayUnsigned();
        return (p, q, g, Convert.FromHexString("3068DDE74863F18A3C6E5CAF244DF178C697A4B6AA087226C1ABE4AB"));
    }
}
