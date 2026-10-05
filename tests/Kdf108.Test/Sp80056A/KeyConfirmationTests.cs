// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Linq;
using System.Security.Cryptography;
using AwesomeAssertions;
using Kdf108.Domain.Sp80056A;
using Kdf108.Domain.Sp80056C;

namespace Kdf108.Test.Sp80056A;

[TestFixture]
public class KeyConfirmationTests
{
    [Test]
    public void ProviderAndRecipient_VerifySameTag()
    {
        var context = new KeyConfirmationContext(
            KeyConfirmationMode.Unilateral,
            KeyConfirmationParty.PartyU,
            "provider"u8,
            "recipient"u8,
            new byte[] { 1, 2 },
            new byte[] { 3, 4 });
        var key = new byte[32];
        var algorithm = KeyConfirmationAlgorithm.HmacFunction(NistHashAlgorithm.Sha256);

        var tag = Sp80056AKeyConfirmation.GenerateTag(
            key, context, algorithm, BitLength.Create(128), SecurityStrength.Bits128);

        Sp80056AKeyConfirmation.VerifyTag(
            tag, key, context, algorithm, BitLength.Create(128), SecurityStrength.Bits128).Should().BeTrue();
    }

    [Test]
    public void MacData_UsesSpecificationConcatenationOrder()
    {
        var context = new KeyConfirmationContext(
            KeyConfirmationMode.Unilateral,
            KeyConfirmationParty.PartyU,
            "U"u8,
            "V"u8,
            new byte[] { 0x01, 0x02 },
            new byte[] { 0x03 },
            "T"u8);
        var key = new byte[32];
        var expectedData = "KC_1_UUV"u8.ToArray()
            .Concat(new byte[] { 0x01, 0x02, 0x03, (byte)'T' })
            .ToArray();
        var expected = HMACSHA256.HashData(key, expectedData).AsSpan(0, 16).ToArray();

        var actual = Sp80056AKeyConfirmation.GenerateTag(
            key,
            context,
            KeyConfirmationAlgorithm.HmacFunction(NistHashAlgorithm.Sha256),
            BitLength.Create(128),
            SecurityStrength.Bits128);

        actual.Should().Equal(expected);
    }

    [Test]
    public void PartyVProvider_ReordersRoleBoundComponents()
    {
        var context = new KeyConfirmationContext(
            KeyConfirmationMode.Bilateral,
            KeyConfirmationParty.PartyV,
            "U"u8,
            "V"u8,
            new byte[] { 0x01 },
            new byte[] { 0x02 });
        var key = new byte[32];
        var expected = HMACSHA256.HashData(
            key,
            "KC_2_VVU"u8.ToArray().Concat(new byte[] { 0x02, 0x01 }).ToArray())
            .AsSpan(0, 16)
            .ToArray();

        var actual = Sp80056AKeyConfirmation.GenerateTag(
            key, context,
            KeyConfirmationAlgorithm.HmacFunction(NistHashAlgorithm.Sha256),
            BitLength.Create(128), SecurityStrength.Bits128);

        actual.Should().Equal(expected);
    }

    [Test]
    public void WrongPartyMarker_DoesNotVerify()
    {
        var provider = new KeyConfirmationContext(
            KeyConfirmationMode.Bilateral, KeyConfirmationParty.PartyU,
            "U"u8, "V"u8, new byte[] { 1 }, new byte[] { 2 });
        var recipient = new KeyConfirmationContext(
            KeyConfirmationMode.Bilateral, KeyConfirmationParty.PartyV,
            "U"u8, "V"u8, new byte[] { 1 }, new byte[] { 2 });
        var key = new byte[32];
        var algorithm = KeyConfirmationAlgorithm.HmacFunction(NistHashAlgorithm.Sha256);
        var tag = Sp80056AKeyConfirmation.GenerateTag(
            key, provider, algorithm, BitLength.Create(128), SecurityStrength.Bits128);

        Sp80056AKeyConfirmation.VerifyTag(
            tag, key, recipient, algorithm, BitLength.Create(128), SecurityStrength.Bits128).Should().BeFalse();
    }

    [Test]
    public void TagShorterThan64Bits_IsRejected()
    {
        var context = new KeyConfirmationContext(
            KeyConfirmationMode.Unilateral, KeyConfirmationParty.PartyU,
            "U"u8, "V"u8, default, default);

        var act = () => Sp80056AKeyConfirmation.GenerateTag(
            new byte[32], context,
            KeyConfirmationAlgorithm.HmacFunction(NistHashAlgorithm.Sha256),
            BitLength.Create(63), SecurityStrength.Bits112);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Test]
    public void Aes256Cmac_Allows256BitTargetStrength()
    {
        var context = new KeyConfirmationContext(
            KeyConfirmationMode.Unilateral, KeyConfirmationParty.PartyU,
            "U"u8, "V"u8, default, default);

        var tag = Sp80056AKeyConfirmation.GenerateTag(
            new byte[32], context,
            KeyConfirmationAlgorithm.AesCmacFunction(256),
            BitLength.Create(128), SecurityStrength.Bits256);

        tag.Should().HaveCount(16);
    }

    [Test]
    public void Kmac_RejectsKeyBelowTargetStrength()
    {
        var context = new KeyConfirmationContext(
            KeyConfirmationMode.Unilateral, KeyConfirmationParty.PartyU,
            "U"u8, "V"u8, default, default);

        var act = () => Sp80056AKeyConfirmation.GenerateTag(
            new byte[16], context,
            KeyConfirmationAlgorithm.Kmac256(BitLength.Create(256)),
            BitLength.Create(128), SecurityStrength.Bits256);

        act.Should().Throw<ArgumentException>().WithMessage("*target strength*");
    }

    [TestCase(16)]
    [TestCase(64)]
    public void HmacSha256_AllowsTable5KeyLengthRangeAt112BitStrength(int keyBytes)
    {
        var tag = Sp80056AKeyConfirmation.GenerateTag(
            new byte[keyBytes], CreateContext(),
            KeyConfirmationAlgorithm.HmacFunction(NistHashAlgorithm.Sha256),
            BitLength.Create(128), SecurityStrength.Bits112);

        tag.Should().HaveCount(16);
    }

    [Test]
    public void HmacSha224_Allows256BitTargetStrength()
    {
        var tag = Sp80056AKeyConfirmation.GenerateTag(
            new byte[32], CreateContext(),
            KeyConfirmationAlgorithm.HmacFunction(NistHashAlgorithm.Sha224),
            BitLength.Create(128), SecurityStrength.Bits256);

        tag.Should().HaveCount(16);
    }

    [TestCase(13, 112)]
    [TestCase(31, 256)]
    public void Hmac_RejectsKeyBelowTargetStrength(int keyBytes, int strengthBits)
    {
        SecurityStrength strength = strengthBits == 112
            ? SecurityStrength.Bits112
            : SecurityStrength.Bits256;

        var act = () => Sp80056AKeyConfirmation.GenerateTag(
            new byte[keyBytes], CreateContext(),
            KeyConfirmationAlgorithm.HmacFunction(NistHashAlgorithm.Sha256),
            BitLength.Create(128), strength);

        act.Should().Throw<ArgumentException>().WithMessage("*target strength*");
    }

    [Test]
    public void Hmac_RejectsKeyLongerThan512Bits()
    {
        var act = () => Sp80056AKeyConfirmation.GenerateTag(
            new byte[65], CreateContext(),
            KeyConfirmationAlgorithm.HmacFunction(NistHashAlgorithm.Sha256),
            BitLength.Create(128), SecurityStrength.Bits112);

        act.Should().Throw<ArgumentException>().WithMessage("*at most 512 bits*");
    }

    private static KeyConfirmationContext CreateContext() => new(
        KeyConfirmationMode.Unilateral, KeyConfirmationParty.PartyU,
        "U"u8, "V"u8, default, default);
}
