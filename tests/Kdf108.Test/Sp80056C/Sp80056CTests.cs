using System;

namespace Kdf108.Test.Nist80056C;

[TestFixture]
[Parallelizable(ParallelScope.All)]
public class Sp80056CTests
{
    [Test]
    public void OneStepHash_MatchesPinnedAnswer() =>
        Assert.That(Sp80056C.OneStep(
                Convert.FromHexString("AFC4E154498D4770AA8365F6903DC83B"),
                OneStepFunction.HashFunction(NistHashAlgorithm.Sha256),
                Convert.FromHexString("662AF20379B29D5EF813E655"),
                BitLength.Create(128), SecurityStrength.Bits128),
            Is.EqualTo(Convert.FromHexString("F0B80D6AE4C1E19E2105A37024E35DC6")));

    [Test]
    public void OneStepHmac_UsesTheSaltAsTheMacKey() =>
        Assert.That(Sp80056C.OneStep(
                Convert.FromHexString("6EE6C00D70A6CD14BD5A4E8FCFEC8386"),
                OneStepFunction.Hmac(NistHashAlgorithm.Sha256, Convert.FromHexString("532F5131E0A2FECC722F87E5AA2062CB")),
                Convert.FromHexString("861AA2886798231259BD0314"),
                BitLength.Create(128), SecurityStrength.Bits128),
            Is.EqualTo(Convert.FromHexString("13479E9A91DD20FDD757D68FFE8869FB")));

    [Test]
    public void OneStep_KeepsExactlyTheRequestedBits()
    {
        byte[] output = Sp80056C.OneStep(Convert.FromHexString("0001020304050607"),
            OneStepFunction.HashFunction(NistHashAlgorithm.Sha256), Convert.FromHexString("A0A1A2"),
            BitLength.Create(9), SecurityStrength.Bits112);
        Assert.That(output, Has.Length.EqualTo(2));
        Assert.That(output[1] & 0x7F, Is.Zero);
    }

    [Test]
    public void OneStepKmac_IsKmacWithCustomizationKdfOverCounterZAndFixedInfo()
    {
        byte[] z = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] fixedInfo = "fixed"u8.ToArray();
        byte[] salt = new byte[32];
        byte[] actual = Sp80056C.OneStep(z, OneStepFunction.KmacFunction(KmacVariant.Kmac128, salt), fixedInfo,
            BitLength.Create(256), SecurityStrength.Bits128);

        var kmac = new Org.BouncyCastle.Crypto.Macs.KMac(128, "KDF"u8.ToArray());
        kmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(salt));
        byte[] input = [0, 0, 0, 1, .. z, .. fixedInfo];
        kmac.BlockUpdate(input, 0, input.Length);
        var expected = new byte[32];
        kmac.OutputFinal(expected, 0, 32);
        Assert.That(actual, Is.EqualTo(expected));
    }

    [Test]
    public void TwoStepHmacCounter_MatchesPinnedAnswer() =>
        Assert.That(Sp80056C.TwoStep(
                Convert.FromHexString("000102030405060708090A0B0C0D0E0F"),
                Extraction.Hmac(NistHashAlgorithm.Sha256, Convert.FromHexString("101112131415161718191A1B1C1D1E1F")),
                KeyExpansion.Counter(Convert.FromHexString("A0A1A2A3A4A5")),
                BitLength.Create(257), SecurityStrength.Bits128),
            Is.EqualTo(Convert.FromHexString("A6F6BD8476D30AB690A3B031B9831CCA1B61352326D8AE2C59B6EE494DFC832780")));

    [Test]
    public void TwoStep_IsExtractThenSp800108WithThePairedPrf()
    {
        byte[] z = new byte[32];
        var extraction = Extraction.AesCmac(256);
        var expansion = KeyExpansion.Feedback("info"u8, "iv"u8);
        byte[] kdk = Sp80056C.Extract(z, extraction, SecurityStrength.Bits128);
        Assert.That(extraction.ExpansionPrf, Is.EqualTo(Prf.AesCmac(128)));
        Assert.That(Sp80056C.TwoStep(z, extraction, expansion, BitLength.Create(200), SecurityStrength.Bits128),
            Is.EqualTo(Sp800108.Derive(kdk, Prf.AesCmac(128), expansion, BitLength.Create(200))));
    }

    [Test]
    public void SaltsAreCopiedOnConstruction()
    {
        byte[] salt = { 1, 2, 3, 4 };
        var function = OneStepFunction.Hmac(NistHashAlgorithm.Sha256, salt);
        byte[] before = Sp80056C.OneStep(new byte[16], function, default, BitLength.Create(128), SecurityStrength.Bits112);
        salt[0] = 9;
        Assert.That(Sp80056C.OneStep(new byte[16], function, default, BitLength.Create(128), SecurityStrength.Bits112), Is.EqualTo(before));
    }

    [Test]
    public void InvalidParametersAreRejected()
    {
        Assert.Throws<KdfParameterException>(() => Extraction.AesCmac(192, new byte[16]));
        Assert.Throws<KdfParameterException>(() => Sp80056C.OneStep(default, OneStepFunction.HashFunction(NistHashAlgorithm.Sha256), default, BitLength.Create(128), SecurityStrength.Bits112));
        Assert.Throws<KdfParameterException>(() => Sp80056C.OneStep(new byte[16], OneStepFunction.HashFunction(NistHashAlgorithm.Sha1), default, BitLength.Create(128), SecurityStrength.Bits192));
        Assert.Throws<KdfParameterException>(() => Sp80056C.OneStep(new byte[16], OneStepFunction.KmacFunction(KmacVariant.Kmac128), default, BitLength.Create(128), SecurityStrength.Bits192));
        Assert.Throws<KdfParameterException>(() => Sp80056C.OneStep(new byte[16], OneStepFunction.KmacFunction(KmacVariant.Kmac128), default, BitLength.Create(129), SecurityStrength.Bits128));
        Assert.Throws<KdfParameterException>(() => Sp80056C.Extract(new byte[16], Extraction.AesCmac(128), SecurityStrength.Bits192));
    }
}
