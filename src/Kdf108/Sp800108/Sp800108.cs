// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Internal;

namespace Kdf108;

/// <summary>The two KMAC functions from SP 800-185.</summary>
public enum KmacVariant
{
    /// <summary>KMAC128: up to 128 bits of security strength.</summary>
    Kmac128,
    /// <summary>KMAC256: up to 256 bits of security strength.</summary>
    Kmac256
}

/// <summary>
/// Key derivation from a uniformly random key-derivation key, per NIST SP 800-108 Rev. 1.
/// </summary>
/// <remarks>
/// Every method takes secrets as spans and returns a new array that the caller owns. Clear it with
/// <see cref="Array.Clear(Array)"/> when you are done. Invalid parameters throw
/// <see cref="KdfParameterException"/>. For dependency injection and logging, use <see cref="ISp800108Kdf"/>.
/// </remarks>
public static class Sp800108
{

    /// <summary>
    /// Derives key material in counter mode with a 32-bit counter and the conventional fixed input
    /// <c>Label || 0x00 || Context || [L]32</c>. This is the right call for most applications.
    /// </summary>
    /// <param name="keyDerivationKey">The key-derivation key K_IN.</param>
    /// <param name="prf">The PRF, for example <c>Prf.Hmac(NistHashAlgorithm.Sha256)</c>.</param>
    /// <param name="label">Identifies the purpose of the derived key.</param>
    /// <param name="context">Binds the key to the parties, session, or other context.</param>
    /// <param name="length">The output length L.</param>
    public static byte[] Derive(
        ReadOnlySpan<byte> keyDerivationKey,
        Prf prf,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> context,
        BitLength length) =>
        Derive(keyDerivationKey, prf, KeyExpansion.Counter(FixedInput(label, context, length)), length);

    /// <summary>Derives key material with any SP 800-108 mode and counter layout.</summary>
    /// <param name="keyDerivationKey">The key-derivation key K_IN.</param>
    /// <param name="prf">The PRF.</param>
    /// <param name="expansion">The mode, fixed input, and counter layout.</param>
    /// <param name="length">The output length L.</param>
    public static byte[] Derive(ReadOnlySpan<byte> keyDerivationKey, Prf prf, KeyExpansion expansion, BitLength length) =>
        Sp800108Engine.Derive(keyDerivationKey, prf, expansion, length);

    /// <summary>The KMAC-based KDF from SP 800-108 Rev. 1 §4.4: one KMAC call with Context as input and Label as customization.</summary>
    /// <param name="keyDerivationKey">The KMAC key. At least 16 bytes for KMAC128 or 32 bytes for KMAC256.</param>
    /// <param name="variant">KMAC128 or KMAC256.</param>
    /// <param name="label">The KMAC customization string S.</param>
    /// <param name="context">The KMAC input X.</param>
    /// <param name="length">The output length L. Must be a whole number of bytes.</param>
    public static byte[] DeriveKmac(
        ReadOnlySpan<byte> keyDerivationKey,
        KmacVariant variant,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> context,
        BitLength length)
    {
        int strength = Strength(variant);
        if (keyDerivationKey.Length * 8 < strength)
            throw new KdfParameterException($"{variant} needs a key of at least {strength / 8} bytes.", nameof(keyDerivationKey));
        if (length.Bits > uint.MaxValue)
            throw new KdfParameterException("Output is limited to 2^32 - 1 bits.", nameof(length));
        return Macs.Kmac(strength, keyDerivationKey, context, label, length.Bits);
    }

    /// <summary>
    /// Builds the conventional fixed input <c>Label || 0x00 || Context || [L]32</c> from SP 800-108r1
    /// §4, with L as a 32-bit big-endian bit count.
    /// </summary>
    public static byte[] FixedInput(ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, BitLength length)
    {
        if (length.Bits > uint.MaxValue)
            throw new KdfParameterException("L must fit in 32 bits.", nameof(length));
        var fixedInput = new byte[label.Length + 1 + context.Length + 4];
        label.CopyTo(fixedInput);
        context.CopyTo(fixedInput.AsSpan(label.Length + 1));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(fixedInput.AsSpan(fixedInput.Length - 4), (uint)length.Bits);
        return fixedInput;
    }

    internal static int Strength(KmacVariant variant) => variant switch
    {
        KmacVariant.Kmac128 => 128,
        KmacVariant.Kmac256 => 256,
        _ => throw new KdfParameterException($"Unknown KMAC variant {variant}.", nameof(variant))
    };
}
