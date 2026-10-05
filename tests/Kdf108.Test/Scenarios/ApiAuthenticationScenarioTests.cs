// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Security.Cryptography;
using System.Text;
using Kdf108.Simple;

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
        using var signer = new HMACSHA256(signingKey);
        using var validator = new HMACSHA256(validationKey);
        byte[] signature = signer.ComputeHash(claims);
        byte[] expected = validator.ComputeHash(claims);

        Assert.That(CryptographicOperations.FixedTimeEquals(signature, expected), Is.True);
    }

    [Test]
    public void RefreshToken_LegacyShortLabelCannotValidateTheSignature()
    {
        byte[] masterKey = new byte[32];
        byte[] context = Encoding.UTF8.GetBytes("user-alice-client-mobile-token-0123456789abcdef");
        byte[] claims = Encoding.UTF8.GetBytes("{\"tokenType\":\"refresh-token\"}");

        using var signer = new HMACSHA256(DeriveSigningKey(masterKey, context, RefreshTokenType));
        using var validator = new HMACSHA256(DeriveSigningKey(masterKey, context, "refresh"));

        Assert.That(
            CryptographicOperations.FixedTimeEquals(signer.ComputeHash(claims), validator.ComputeHash(claims)),
            Is.False);
    }

    private static byte[] DeriveSigningKey(byte[] masterKey, byte[] context, string tokenType) =>
        SecureKeyDerivation.DeriveKey(masterKey, $"{tokenType}-signing-v1", 32, context);
}
