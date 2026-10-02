// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.IO;
using System.Linq;
using AwesomeAssertions;
using Kdf108.Domain.Sp80056A;

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
}
