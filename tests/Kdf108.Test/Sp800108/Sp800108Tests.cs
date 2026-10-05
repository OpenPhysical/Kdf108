using System;
using System.Linq;
using System.Text;

namespace Kdf108.Test.Nist800108;

[TestFixture]
[Parallelizable(ParallelScope.All)]
public class Sp800108Tests
{
    private static readonly byte[] Key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
    private static readonly byte[] Label = "TestLabel"u8.ToArray();
    private static readonly byte[] Context = "Vault:1|Box:2|Item:3"u8.ToArray();
    private static readonly Prf HmacSha256 = Prf.Hmac(NistHashAlgorithm.Sha256);

    [Test]
    public void CounterMode_MatchesPinnedAnswer()
    {
        byte[] actual = Sp800108.Derive(Key, HmacSha256, Label, Context, BitLength.Create(256));
        Assert.That(actual, Is.EqualTo(Convert.FromHexString("D39D601E90C9B0CB45B2E841313D0D4172A1B3C52AA8D049302B401AEB9EDFB6")));
    }

    [Test]
    public void ConvenienceOverload_IsCounterModeWithConventionalFixedInput()
    {
        var length = BitLength.Create(384);
        byte[] viaOverload = Sp800108.Derive(Key, HmacSha256, Label, Context, length);
        byte[] explicitly = Sp800108.Derive(Key, HmacSha256,
            KeyExpansion.Counter(Sp800108.FixedInput(Label, Context, length), 32, CounterPosition.BeforeFixedInput), length);
        Assert.That(viaOverload, Is.EqualTo(explicitly));
    }

    [Test]
    public void FixedInput_IsLabelZeroContextAndBigEndianLength()
    {
        byte[] fixedInput = Sp800108.FixedInput("AB"u8, "C"u8, BitLength.Create(0x0102));
        Assert.That(fixedInput, Is.EqualTo(new byte[] { (byte)'A', (byte)'B', 0, (byte)'C', 0, 0, 1, 2 }));
    }

    // Regression: the old 8-bit CMAC counter-mode path reproduced this answer only through a raw split call.
    [Test]
    public void CmacCounterMode_MatchesPinnedAnswer()
    {
        byte[] actual = Sp800108.Derive(
            Convert.FromHexString("DFF1E50AC0B69DC40F1051D46C2B069C"), Prf.AesCmac(128),
            KeyExpansion.Counter(Convert.FromHexString(
                "C16E6E02C5A3DCC8D78B9AC1306877761310455B4E41469951D9E6C2245A064B33FD8C3B01203A7824485BF0A64060C4648B707D2607935699316EA5"), 8),
            BitLength.Create(128));
        Assert.That(actual, Is.EqualTo(Convert.FromHexString("8BE8F0869B3C0BA97B71863D1B9F7813")));
    }

    [TestCase(1)]
    [TestCase(7)]
    [TestCase(9)]
    [TestCase(257)]
    public void EveryMode_KeepsExactlyTheRequestedBits(int bits)
    {
        foreach (KeyExpansion expansion in AllModes())
        {
            byte[] output = Sp800108.Derive(Key, HmacSha256, expansion, BitLength.Create(bits));
            int unused = (output.Length * 8) - bits;
            Assert.That(output, Has.Length.EqualTo((bits + 7) / 8), expansion.Mode.ToString());
            Assert.That(output[^1] & ((1 << unused) - 1), Is.Zero, expansion.Mode.ToString());
        }
    }

    [Test]
    public void ShorterOutputIsAPrefixOnlyWhenFixedInputIsShared()
    {
        var fixedInput = Sp800108.FixedInput(Label, Context, BitLength.Create(512));
        byte[] full = Sp800108.Derive(Key, HmacSha256, KeyExpansion.Counter(fixedInput), BitLength.Create(512));
        byte[] part = Sp800108.Derive(Key, HmacSha256, KeyExpansion.Counter(fixedInput), BitLength.Create(256));
        Assert.That(part, Is.EqualTo(full[..32]));
        // Encoding L in the fixed input makes different lengths independent.
        Assert.That(Sp800108.Derive(Key, HmacSha256, Label, Context, BitLength.Create(256)), Is.Not.EqualTo(full[..32]));
    }

    [Test]
    public void LabelsContextsModesAndLayoutsAllSeparateKeys()
    {
        var length = BitLength.Create(256);
        var outputs = new[]
        {
            Sp800108.Derive(Key, HmacSha256, "café"u8, Context, length),
            Sp800108.Derive(Key, HmacSha256, Encoding.UTF8.GetBytes("cafñ"), Context, length),
            Sp800108.Derive(Key, HmacSha256, Label, "Vault:A"u8, length),
        }.Concat(AllModes().Select(e => Sp800108.Derive(Key, HmacSha256, e, length))).ToList();
        Assert.That(outputs.Select(Convert.ToHexString).Distinct().Count(), Is.EqualTo(outputs.Count));
    }

    [TestCase(1)]
    [TestCase(9)]
    [TestCase(31)]
    [TestCase(33)]
    public void CounterWidthsOutsideTheCavpSetAreRejected(int bits) =>
        Assert.Throws<KdfParameterException>(() => KeyExpansion.Counter(Context, bits));

    [Test]
    public void OutputBeyondTheCounterIsRejected()
    {
        // An 8-bit counter numbers 255 HMAC-SHA256 blocks.
        Assert.That(Sp800108.Derive(Key, HmacSha256, KeyExpansion.Counter(Context, 8), BitLength.Create(255 * 256)), Has.Length.EqualTo(255 * 32));
        var ex = Assert.Throws<KdfParameterException>(() =>
            Sp800108.Derive(Key, HmacSha256, KeyExpansion.Counter(Context, 8), BitLength.Create((255 * 256) + 1)));
        Assert.That(ex!.Message, Does.Contain("8-bit counter"));
    }

    [Test]
    public void OutputBeyondThirtyTwoBitLengthIsRejected() =>
        Assert.Throws<KdfParameterException>(() => Sp800108.Derive(Key, HmacSha256, Label, Context, BitLength.Create(1L << 32)));

    [TestCase(128, 15)]
    [TestCase(192, 16)]
    [TestCase(256, 24)]
    public void CmacRejectsTheWrongKeySize(int keyBits, int keyBytes) =>
        Assert.Throws<KdfParameterException>(() =>
            Sp800108.Derive(new byte[keyBytes], Prf.AesCmac(keyBits), Label, Context, BitLength.Create(128)));

    [Test]
    public void EmptyKeyIsRejected() =>
        Assert.Throws<KdfParameterException>(() => Sp800108.Derive(ReadOnlySpan<byte>.Empty, HmacSha256, Label, Context, BitLength.Create(128)));

    [Test]
    public void NonPositiveLengthsAreRejected()
    {
        Assert.Throws<KdfParameterException>(() => BitLength.Create(0));
        Assert.Throws<KdfParameterException>(() => BitLength.Create(-1));
    }

    [Test]
    public void EveryApprovedHmacAndCmacWorks()
    {
        foreach (NistHashAlgorithm hash in Enum.GetValues<NistHashAlgorithm>())
            Assert.That(Sp800108.Derive(Key, Prf.Hmac(hash), Label, Context, BitLength.Create(1024)), Has.Length.EqualTo(128), hash.ToString());
        foreach (int bits in new[] { 128, 192, 256 })
            Assert.That(Sp800108.Derive(new byte[bits / 8], Prf.AesCmac(bits), Label, Context, BitLength.Create(1024)), Has.Length.EqualTo(128));
    }

    private static readonly byte[] KmacKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");

    // NIST SP 800-185 KMAC samples. SP 800-108r1 §4.4 maps X to Context and S to Label.
    [TestCase(KmacVariant.Kmac128, "", 256, "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E")]
    [TestCase(KmacVariant.Kmac128, "My Tagged Application", 256, "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5")]
    [TestCase(KmacVariant.Kmac256, "My Tagged Application", 512, "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD")]
    public void Kmac_MatchesSp800185Samples(KmacVariant variant, string label, int bits, string expected)
    {
        byte[] actual = Sp800108.DeriveKmac(KmacKey, variant, Encoding.ASCII.GetBytes(label), Convert.FromHexString("00010203"), BitLength.Create(bits));
        Assert.That(actual, Is.EqualTo(Convert.FromHexString(expected)));
    }

    [Test]
    public void KmacRejectsNonOctetLengthsAndShortKeys()
    {
        Assert.Throws<KdfParameterException>(() => Sp800108.DeriveKmac(KmacKey, KmacVariant.Kmac128, default, default, BitLength.Create(255)));
        Assert.Throws<KdfParameterException>(() => Sp800108.DeriveKmac(new byte[15], KmacVariant.Kmac128, default, default, BitLength.Create(256)));
        Assert.Throws<KdfParameterException>(() => Sp800108.DeriveKmac(new byte[31], KmacVariant.Kmac256, default, default, BitLength.Create(256)));
    }

    private static KeyExpansion[] AllModes() =>
    [
        KeyExpansion.Counter(Context, 32, CounterPosition.BeforeFixedInput),
        KeyExpansion.Counter(Context, 32, CounterPosition.AfterFixedInput),
        KeyExpansion.CounterInMiddle("before"u8, "after"u8),
        KeyExpansion.Feedback(Context, "iv"u8),
        KeyExpansion.Feedback(Context, "iv"u8, position: IterationCounterPosition.BeforeIteration),
        KeyExpansion.Feedback(Context, "iv"u8, position: IterationCounterPosition.AfterFixedInput),
        KeyExpansion.Feedback(Context, default, useCounter: false),
        KeyExpansion.DoublePipeline(Context),
        KeyExpansion.DoublePipeline(Context, position: IterationCounterPosition.BeforeIteration),
        KeyExpansion.DoublePipeline(Context, useCounter: false),
    ];
}
