// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Text;
using Kdf108.Simple;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Test.Scenarios;

[TestFixture]
public class ApiAuthenticationScenarioTests
{
    private const string RefreshTokenType = "refresh-token";

    [Test]
    public void RefreshToken_SigningAndValidationDeriveTheSameKey()
    {
        byte[] masterKey = new byte[32];
        byte[] context = Encoding.UTF8.GetBytes("user-alice-client-mobile-token-0123456789abcdef");
        byte[] claims = Encoding.UTF8.GetBytes("{\"tokenType\":\"refresh-token\"}");

        byte[] signingKey = DeriveSigningKey(masterKey, context, RefreshTokenType);
        byte[] validationKey = DeriveSigningKey(masterKey, context, RefreshTokenType);
        byte[] signature = HmacSha256(signingKey, claims);
        byte[] expected = HmacSha256(validationKey, claims);

        Assert.That(signature, Is.EqualTo(expected));
    }

    [Test]
    public void RefreshToken_LegacyShortLabelCannotValidateTheSignature()
    {
        byte[] masterKey = new byte[32];
        byte[] context = Encoding.UTF8.GetBytes("user-alice-client-mobile-token-0123456789abcdef");
        byte[] claims = Encoding.UTF8.GetBytes("{\"tokenType\":\"refresh-token\"}");

        Assert.That(
            HmacSha256(DeriveSigningKey(masterKey, context, RefreshTokenType), claims),
            Is.Not.EqualTo(HmacSha256(DeriveSigningKey(masterKey, context, "refresh"), claims)),
            "legacy key-separation label must not validate");
    }

    private static byte[] DeriveSigningKey(byte[] masterKey, byte[] context, string tokenType) =>
        SecureKeyDerivation.DeriveKey(masterKey, $"{tokenType}-signing-v1", 32, context);

    private static byte[] HmacSha256(byte[] key, byte[] data)
    {
        var mac = new HMac(new Sha256Digest());
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data, 0, data.Length);
        var result = new byte[mac.GetMacSize()];
        mac.DoFinal(result, 0);
        return result;
    }
}
