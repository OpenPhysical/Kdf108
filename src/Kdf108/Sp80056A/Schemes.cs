// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108;

/// <summary>
/// The SP 800-56A Rev. 3 ECC key-agreement schemes. <see cref="FfcSchemes"/> has the same methods for
/// finite fields. Each returns the shared secret Z, which you must pass through an SP 800-56C KDF
/// (<see cref="Sp80056C"/>) before use, then clear.
/// For dependency injection and logging, use <see cref="IEcKeyAgreement"/>.
/// </summary>
/// <remarks>
/// Method names follow the scheme categories of §6: <c>Ephemeral</c> is C(2e, 0s) "Ephemeral Unified",
/// <c>Static</c> is C(0e, 2s) "Static Unified", <c>OneFlow</c> is C(1e, 1s) "One-Pass Diffie-Hellman",
/// <c>Hybrid</c> is C(2e, 2s) "Full Unified", <c>HybridOneFlow</c> is C(1e, 2s) "One-Pass Unified",
/// <c>Mqv2</c> is "Full MQV", and <c>Mqv1</c> is "One-Pass MQV". Party U is the initiator, V the responder.
/// </remarks>
public static class EcSchemes
{
    /// <summary>Ephemeral Unified, C(2e, 0s): Z = ECC CDH(local ephemeral, remote ephemeral).</summary>
    public static byte[] Ephemeral(EcEphemeralKeyPair localEphemeral, EcEphemeralPublicKey remoteEphemeral) =>
        (Cdh(localEphemeral.Domain, localEphemeral.D, remoteEphemeral));

    /// <summary>Static Unified, C(0e, 2s): Z = ECC CDH(local static, remote static).</summary>
    public static byte[] Static(EcStaticKeyPair localStatic, EcStaticPublicKey remoteStatic) =>
        (Cdh(localStatic.Domain, localStatic.D, remoteStatic));

    /// <summary>One-Pass Diffie-Hellman, C(1e, 1s), as party U: Z = ECC CDH(U's ephemeral, V's static).</summary>
    public static byte[] OneFlowAsPartyU(EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic) =>
        (Cdh(localEphemeral.Domain, localEphemeral.D, remoteStatic));

    /// <summary>One-Pass Diffie-Hellman, C(1e, 1s), as party V: Z = ECC CDH(V's static, U's ephemeral).</summary>
    public static byte[] OneFlowAsPartyV(EcStaticKeyPair localStatic, EcEphemeralPublicKey remoteEphemeral) =>
        (Cdh(localStatic.Domain, localStatic.D, remoteEphemeral));

    /// <summary>Full Unified, C(2e, 2s): Z = Ze || Zs.</summary>
    public static byte[] Hybrid(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral) =>
        (SharedSecrets.Concatenate(
            Cdh(localEphemeral.Domain, localEphemeral.D, remoteEphemeral, localStatic.Domain),
            () => Cdh(localStatic.Domain, localStatic.D, remoteStatic)));

    /// <summary>One-Pass Unified, C(1e, 2s), as party U: Z = CDH(U's ephemeral, V's static) || CDH(U's static, V's static).</summary>
    public static byte[] HybridOneFlowAsPartyU(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic) =>
        (SharedSecrets.Concatenate(
            Cdh(localEphemeral.Domain, localEphemeral.D, remoteStatic, localStatic.Domain),
            () => Cdh(localStatic.Domain, localStatic.D, remoteStatic)));

    /// <summary>One-Pass Unified, C(1e, 2s), as party V: Z = CDH(V's static, U's ephemeral) || CDH(V's static, U's static).</summary>
    public static byte[] HybridOneFlowAsPartyV(EcStaticKeyPair localStatic, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral) =>
        (SharedSecrets.Concatenate(
            Cdh(localStatic.Domain, localStatic.D, remoteEphemeral, remoteStatic.Domain),
            () => Cdh(localStatic.Domain, localStatic.D, remoteStatic)));

    /// <summary>Full MQV, C(2e, 2s).</summary>
    public static byte[] Mqv2(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral)
    {
        Same(localStatic.Domain, localEphemeral.Domain, remoteStatic.Domain, remoteEphemeral.Domain);
        return EcPrimitives.Mqv(localStatic.Domain, localStatic.D, localEphemeral.D, localEphemeral.PublicKey.Point, remoteStatic.Point, remoteEphemeral.Point);
    }

    /// <summary>One-Pass MQV, C(1e, 2s), as party U: V's static key stands in for V's ephemeral key.</summary>
    public static byte[] Mqv1AsPartyU(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic)
    {
        Same(localStatic.Domain, localEphemeral.Domain, remoteStatic.Domain);
        return EcPrimitives.Mqv(localStatic.Domain, localStatic.D, localEphemeral.D, localEphemeral.PublicKey.Point, remoteStatic.Point, remoteStatic.Point);
    }

    /// <summary>One-Pass MQV, C(1e, 2s), as party V: V's static key stands in for its own ephemeral key.</summary>
    public static byte[] Mqv1AsPartyV(EcStaticKeyPair localStatic, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral)
    {
        Same(localStatic.Domain, remoteStatic.Domain, remoteEphemeral.Domain);
        return EcPrimitives.Mqv(localStatic.Domain, localStatic.D, localStatic.D, localStatic.PublicKey.Point, remoteStatic.Point, remoteEphemeral.Point);
    }

    private static byte[] Cdh(EcDomain domain, Org.BouncyCastle.Math.BigInteger d, EcPublicKey remote, EcDomain? alsoSameAs = null)
    {
        Same(domain, remote.Domain, alsoSameAs ?? domain);
        return EcPrimitives.Cdh(domain, d, remote.Point);
    }

    private static void Same(params EcDomain[] domains)
    {
        foreach (EcDomain domain in domains)
        {
            if (!ReferenceEquals(domain, domains[0]))
                throw new InvalidKeyException(KeyFailure.DomainMismatch, $"Keys on {domains[0]} and {domain} cannot be combined.");
        }
    }

}

/// <summary>
/// The SP 800-56A Rev. 3 FFC key-agreement schemes, with the same methods as <see cref="EcSchemes"/>.
/// Each returns the shared secret Z, which you must pass through an SP 800-56C KDF before use, then clear.
/// For dependency injection and logging, use <see cref="IFfcKeyAgreement"/>.
/// </summary>
/// <remarks>
/// <c>Ephemeral</c> is dhEphem, <c>Static</c> is dhStatic, <c>OneFlow</c> is dhOneFlow, <c>Hybrid</c> is
/// dhHybrid1, <c>HybridOneFlow</c> is dhHybridOneFlow, <c>Mqv2</c> is MQV2, and <c>Mqv1</c> is MQV1.
/// </remarks>
public static class FfcSchemes
{
    /// <summary>dhEphem, C(2e, 0s): Z = FFC DH(local ephemeral, remote ephemeral).</summary>
    public static byte[] Ephemeral(FfcEphemeralKeyPair localEphemeral, FfcEphemeralPublicKey remoteEphemeral) =>
        (Dh(localEphemeral.Domain, localEphemeral.X, remoteEphemeral));

    /// <summary>dhStatic, C(0e, 2s): Z = FFC DH(local static, remote static).</summary>
    public static byte[] Static(FfcStaticKeyPair localStatic, FfcStaticPublicKey remoteStatic) =>
        (Dh(localStatic.Domain, localStatic.X, remoteStatic));

    /// <summary>dhOneFlow, C(1e, 1s), as party U: Z = FFC DH(U's ephemeral, V's static).</summary>
    public static byte[] OneFlowAsPartyU(FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic) =>
        (Dh(localEphemeral.Domain, localEphemeral.X, remoteStatic));

    /// <summary>dhOneFlow, C(1e, 1s), as party V: Z = FFC DH(V's static, U's ephemeral).</summary>
    public static byte[] OneFlowAsPartyV(FfcStaticKeyPair localStatic, FfcEphemeralPublicKey remoteEphemeral) =>
        (Dh(localStatic.Domain, localStatic.X, remoteEphemeral));

    /// <summary>dhHybrid1, C(2e, 2s): Z = Ze || Zs.</summary>
    public static byte[] Hybrid(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral) =>
        (SharedSecrets.Concatenate(
            Dh(localEphemeral.Domain, localEphemeral.X, remoteEphemeral, localStatic.Domain),
            () => Dh(localStatic.Domain, localStatic.X, remoteStatic)));

    /// <summary>dhHybridOneFlow, C(1e, 2s), as party U: Z = DH(U's ephemeral, V's static) || DH(U's static, V's static).</summary>
    public static byte[] HybridOneFlowAsPartyU(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic) =>
        (SharedSecrets.Concatenate(
            Dh(localEphemeral.Domain, localEphemeral.X, remoteStatic, localStatic.Domain),
            () => Dh(localStatic.Domain, localStatic.X, remoteStatic)));

    /// <summary>dhHybridOneFlow, C(1e, 2s), as party V: Z = DH(V's static, U's ephemeral) || DH(V's static, U's static).</summary>
    public static byte[] HybridOneFlowAsPartyV(FfcStaticKeyPair localStatic, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral) =>
        (SharedSecrets.Concatenate(
            Dh(localStatic.Domain, localStatic.X, remoteEphemeral, remoteStatic.Domain),
            () => Dh(localStatic.Domain, localStatic.X, remoteStatic)));

    /// <summary>MQV2, C(2e, 2s).</summary>
    public static byte[] Mqv2(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral)
    {
        Same(localStatic.Domain, localEphemeral.Domain, remoteStatic.Domain, remoteEphemeral.Domain);
        return FfcPrimitives.Mqv(localStatic.Domain, localStatic.X, localEphemeral.X, localEphemeral.PublicKey.Y, remoteStatic.Y, remoteEphemeral.Y);
    }

    /// <summary>MQV1, C(1e, 2s), as party U: V's static key stands in for V's ephemeral key.</summary>
    public static byte[] Mqv1AsPartyU(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic)
    {
        Same(localStatic.Domain, localEphemeral.Domain, remoteStatic.Domain);
        return FfcPrimitives.Mqv(localStatic.Domain, localStatic.X, localEphemeral.X, localEphemeral.PublicKey.Y, remoteStatic.Y, remoteStatic.Y);
    }

    /// <summary>MQV1, C(1e, 2s), as party V: V's static key stands in for its own ephemeral key.</summary>
    public static byte[] Mqv1AsPartyV(FfcStaticKeyPair localStatic, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral)
    {
        Same(localStatic.Domain, remoteStatic.Domain, remoteEphemeral.Domain);
        return FfcPrimitives.Mqv(localStatic.Domain, localStatic.X, localStatic.X, localStatic.PublicKey.Y, remoteStatic.Y, remoteEphemeral.Y);
    }

    private static byte[] Dh(FfcDomain domain, Org.BouncyCastle.Math.BigInteger x, FfcPublicKey remote, FfcDomain? alsoSameAs = null)
    {
        Same(domain, remote.Domain, alsoSameAs ?? domain);
        return FfcPrimitives.Dh(domain, x, remote.Y);
    }

    private static void Same(params FfcDomain[] domains)
    {
        foreach (FfcDomain domain in domains)
        {
            if (!domain.SameAs(domains[0]))
                throw new InvalidKeyException(KeyFailure.DomainMismatch, "Keys from different FFC domains cannot be combined.");
        }
    }

}

internal static class SharedSecrets
{
    /// <summary>Ze || Zs. Both parts are cleared, including when computing the second fails.</summary>
    internal static byte[] Concatenate(byte[] first, Func<byte[]> computeSecond)
    {
        byte[]? second = null;
        try
        {
            second = computeSecond();
            var z = new byte[first.Length + second.Length];
            first.CopyTo(z, 0);
            second.CopyTo(z, first.Length);
            return z;
        }
        finally
        {
            Array.Clear(first);
            if (second is not null) Array.Clear(second);
        }
    }
}
