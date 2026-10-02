// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#pragma warning disable CS1591

using System;
using System.Security.Cryptography;

namespace Kdf108.Domain.Sp80056A;

/// <summary>Role-safe shared-secret computations for the FFC schemes in SP 800-56A Rev. 3.</summary>
public static class FfcSchemes
{
    public static byte[] DhEphemeral(FfcEphemeralKeyPair localEphemeral, FfcEphemeralPublicKey remoteEphemeral) =>
        FfcKeyAgreement.DiffieHellman(localEphemeral, remoteEphemeral);

    public static byte[] DhStatic(FfcStaticKeyPair localStatic, FfcStaticPublicKey remoteStatic) =>
        FfcKeyAgreement.DiffieHellman(localStatic, remoteStatic);

    public static byte[] DhOneFlowAsPartyU(FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic) =>
        FfcKeyAgreement.DiffieHellman(localEphemeral, remoteStatic);

    public static byte[] DhOneFlowAsPartyV(FfcStaticKeyPair localStatic, FfcEphemeralPublicKey remoteEphemeral) =>
        FfcKeyAgreement.DiffieHellman(localStatic, remoteEphemeral);

    public static byte[] DhHybrid1(
        FfcStaticKeyPair localStatic,
        FfcEphemeralKeyPair localEphemeral,
        FfcStaticPublicKey remoteStatic,
        FfcEphemeralPublicKey remoteEphemeral)
    {
        var ze = FfcKeyAgreement.DiffieHellman(localEphemeral, remoteEphemeral);
        var zs = FfcKeyAgreement.DiffieHellman(localStatic, remoteStatic);
        return ConcatenateAndClear(ze, zs);
    }

    public static byte[] DhHybridOneFlowAsPartyU(
        FfcStaticKeyPair localStatic,
        FfcEphemeralKeyPair localEphemeral,
        FfcStaticPublicKey remoteStatic)
    {
        var ze = FfcKeyAgreement.DiffieHellman(localEphemeral, remoteStatic);
        var zs = FfcKeyAgreement.DiffieHellman(localStatic, remoteStatic);
        return ConcatenateAndClear(ze, zs);
    }

    public static byte[] DhHybridOneFlowAsPartyV(
        FfcStaticKeyPair localStatic,
        FfcStaticPublicKey remoteStatic,
        FfcEphemeralPublicKey remoteEphemeral)
    {
        var ze = FfcKeyAgreement.DiffieHellman(localStatic, remoteEphemeral);
        var zs = FfcKeyAgreement.DiffieHellman(localStatic, remoteStatic);
        return ConcatenateAndClear(ze, zs);
    }

    public static byte[] Mqv2(
        FfcStaticKeyPair localStatic,
        FfcEphemeralKeyPair localEphemeral,
        FfcStaticPublicKey remoteStatic,
        FfcEphemeralPublicKey remoteEphemeral) =>
        FfcKeyAgreement.Mqv(localStatic, localEphemeral, remoteStatic, remoteEphemeral);

    public static byte[] Mqv1AsPartyU(
        FfcStaticKeyPair localStatic,
        FfcEphemeralKeyPair localEphemeral,
        FfcStaticPublicKey remoteStatic) =>
        FfcKeyAgreement.Mqv1AsPartyU(localStatic, localEphemeral, remoteStatic);

    public static byte[] Mqv1AsPartyV(
        FfcStaticKeyPair localStatic,
        FfcStaticPublicKey remoteStatic,
        FfcEphemeralPublicKey remoteEphemeral) =>
        FfcKeyAgreement.Mqv1AsPartyV(localStatic, remoteStatic, remoteEphemeral);

    private static byte[] ConcatenateAndClear(byte[] first, byte[] second)
    {
        try
        {
            var result = new byte[checked(first.Length + second.Length)];
            Buffer.BlockCopy(first, 0, result, 0, first.Length);
            Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
    }
}
