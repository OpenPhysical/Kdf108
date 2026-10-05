using System;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Test.Nist80056A;

[TestFixture]
[Parallelizable(ParallelScope.All)]
public class KeyConfirmationTests
{
    private static readonly KeyConfirmationMac HmacSha256 = KeyConfirmationMac.Hmac(NistHashAlgorithm.Sha256);
    private static readonly BitLength Tag128 = BitLength.Create(128);

    [Test]
    public void MacDataFollowsTheSpecifiedOrderForPartyU()
    {
        var context = new KeyConfirmationContext(KeyConfirmationMode.Unilateral, Party.U, "U"u8, "V"u8, [0x01, 0x02], [0x03], "T"u8);
        Assert.That(context.EncodeMacData(), Is.EqualTo((byte[])[.. "KC_1_UUV"u8, 0x01, 0x02, 0x03, (byte)'T']));
        Assert.That(KeyConfirmation.GenerateTag(new byte[32], context, HmacSha256, Tag128, SecurityStrength.Bits128),
            Is.EqualTo(Hmac(new byte[32], context.EncodeMacData())[..16]));
    }

    [Test]
    public void PartyVReordersTheRoleBoundComponents()
    {
        var context = new KeyConfirmationContext(KeyConfirmationMode.Bilateral, Party.V, "U"u8, "V"u8, [0x01], [0x02]);
        Assert.That(context.EncodeMacData(), Is.EqualTo((byte[])[.. "KC_2_VVU"u8, 0x02, 0x01]));
    }

    [Test]
    public void RecipientVerifiesAndAWrongProviderDoesNot()
    {
        var u = new KeyConfirmationContext(KeyConfirmationMode.Bilateral, Party.U, "U"u8, "V"u8, [1], [2]);
        var v = new KeyConfirmationContext(KeyConfirmationMode.Bilateral, Party.V, "U"u8, "V"u8, [1], [2]);
        byte[] tag = KeyConfirmation.GenerateTag(new byte[32], u, HmacSha256, Tag128, SecurityStrength.Bits128);
        Assert.That(KeyConfirmation.VerifyTag(tag, new byte[32], u, HmacSha256, Tag128, SecurityStrength.Bits128), Is.True);
        Assert.That(KeyConfirmation.VerifyTag(tag, new byte[32], v, HmacSha256, Tag128, SecurityStrength.Bits128), Is.False);
    }

    // Regression: KMAC key confirmation must use customization string "KC" (SP 800-56A Rev. 3, ACVP KAS)
    // with KMAC's output length L equal to MacTagLen.
    [TestCase(KmacVariant.Kmac128, 128)]
    [TestCase(KmacVariant.Kmac256, 256)]
    public void KmacUsesCustomizationKcAndTagLengthAsL(KmacVariant variant, int strength)
    {
        var context = Context();
        byte[] key = new byte[32];
        byte[] tag = KeyConfirmation.GenerateTag(key, context, KeyConfirmationMac.KmacFunction(variant), BitLength.Create(192),
            strength == 128 ? SecurityStrength.Bits128 : SecurityStrength.Bits256);

        var kmac = new KMac(strength, "KC"u8.ToArray());
        kmac.Init(new KeyParameter(key));
        byte[] data = context.EncodeMacData();
        kmac.BlockUpdate(data, 0, data.Length);
        var expected = new byte[24];
        kmac.OutputFinal(expected, 0, expected.Length);
        Assert.That(tag, Is.EqualTo(expected));
    }

    [TestCase(16)]
    [TestCase(64)]
    public void HmacAcceptsTheTable5KeyRange(int keyBytes) =>
        Assert.That(KeyConfirmation.GenerateTag(new byte[keyBytes], Context(), HmacSha256, Tag128, SecurityStrength.Bits112), Has.Length.EqualTo(16));

    [Test]
    public void ParametersOutsideTheStandardAreRejected()
    {
        Assert.Throws<KdfParameterException>(() => KeyConfirmation.GenerateTag(new byte[32], Context(), HmacSha256, BitLength.Create(63), SecurityStrength.Bits112));
        Assert.Throws<KdfParameterException>(() => KeyConfirmation.GenerateTag(new byte[32], Context(), HmacSha256, BitLength.Create(264), SecurityStrength.Bits112));
        Assert.Throws<KdfParameterException>(() => KeyConfirmation.GenerateTag(new byte[13], Context(), HmacSha256, Tag128, SecurityStrength.Bits112));
        Assert.Throws<KdfParameterException>(() => KeyConfirmation.GenerateTag(new byte[31], Context(), HmacSha256, Tag128, SecurityStrength.Bits256));
        Assert.Throws<KdfParameterException>(() => KeyConfirmation.GenerateTag(new byte[65], Context(), HmacSha256, Tag128, SecurityStrength.Bits112));
        Assert.Throws<KdfParameterException>(() => KeyConfirmation.GenerateTag(new byte[16], Context(), KeyConfirmationMac.KmacFunction(KmacVariant.Kmac256), Tag128, SecurityStrength.Bits256));
        Assert.Throws<KdfParameterException>(() => KeyConfirmation.GenerateTag(new byte[16], Context(), KeyConfirmationMac.AesCmac(128), Tag128, SecurityStrength.Bits192));
        Assert.Throws<KdfParameterException>(() => KeyConfirmation.GenerateTag(new byte[16], Context(), KeyConfirmationMac.AesCmac(256), Tag128, SecurityStrength.Bits112));
        Assert.Throws<KdfParameterException>(() => new KeyConfirmationContext(KeyConfirmationMode.Unilateral, Party.U, default, "V"u8, default, default));
    }

    [Test]
    public void Aes256CmacSupports256BitStrength() =>
        Assert.That(KeyConfirmation.GenerateTag(new byte[32], Context(), KeyConfirmationMac.AesCmac(256), Tag128, SecurityStrength.Bits256), Has.Length.EqualTo(16));

    private static KeyConfirmationContext Context() => new(KeyConfirmationMode.Unilateral, Party.U, "U"u8, "V"u8, default, default);

    private static byte[] Hmac(byte[] key, byte[] data)
    {
        var mac = new HMac(new Sha256Digest());
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data, 0, data.Length);
        var result = new byte[32];
        mac.DoFinal(result, 0);
        return result;
    }
}
