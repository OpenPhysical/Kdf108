// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Domain.Sp800108;

/// <summary>Selects the KMAC function used by the SP 800-108 KMAC KDF.</summary>
public enum Sp800108KmacAlgorithm
{
    /// <summary>KMAC128, providing at most 128 bits of security strength.</summary>
    Kmac128,

    /// <summary>KMAC256, providing at most 256 bits of security strength.</summary>
    Kmac256
}

/// <summary>Implements the dedicated KMAC KDF from NIST SP 800-108 Rev. 1, Section 4.4.</summary>
/// <remarks>
/// This is a single KMAC invocation. It is deliberately separate from the iterative counter,
/// feedback, and double-pipeline KDFs. The label is the KMAC customization string and the
/// context is the KMAC main input.
/// </remarks>
public static class Sp800108Kmac
{
    /// <summary>The default implementation limit for derived output, in bits.</summary>
    public const int DefaultMaximumOutputBits = 8192;

    /// <summary>Derives keying material with KMAC128 or KMAC256.</summary>
    /// <param name="keyDerivationKey">The KMAC key, KIN.</param>
    /// <param name="context">The KMAC main input, Context.</param>
    /// <param name="outputLengthBits">The requested output length, L, in bits.</param>
    /// <param name="algorithm">The approved KMAC function.</param>
    /// <param name="label">The optional KMAC customization string, Label.</param>
    /// <param name="maximumOutputBits">An application resource limit applied before allocation.</param>
    /// <returns>The derived keying material.</returns>
    /// <exception cref="ArgumentException">The key is too short or the output length is not octet-aligned.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The algorithm or output length is invalid.</exception>
    public static byte[] DeriveKey(
        ReadOnlySpan<byte> keyDerivationKey,
        ReadOnlySpan<byte> context,
        int outputLengthBits,
        Sp800108KmacAlgorithm algorithm = Sp800108KmacAlgorithm.Kmac128,
        ReadOnlySpan<byte> label = default,
        int maximumOutputBits = DefaultMaximumOutputBits)
    {
        if (maximumOutputBits <= 0)
            throw new ArgumentOutOfRangeException(nameof(maximumOutputBits), "The implementation output limit must be positive.");
        if (outputLengthBits <= 0 || outputLengthBits > maximumOutputBits)
            throw new ArgumentOutOfRangeException(nameof(outputLengthBits), $"The output length must be between 1 and {maximumOutputBits} bits.");
        if ((outputLengthBits & 7) != 0)
            throw new ArgumentException("This implementation requires an octet-aligned output length.", nameof(outputLengthBits));

        int strength = algorithm switch
        {
            Sp800108KmacAlgorithm.Kmac128 => 128,
            Sp800108KmacAlgorithm.Kmac256 => 256,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };
        int minimumKeyBytes = strength / 8;
        if (keyDerivationKey.Length < minimumKeyBytes)
            throw new ArgumentException($"{algorithm} requires a key of at least {minimumKeyBytes} bytes.", nameof(keyDerivationKey));

        byte[] key = keyDerivationKey.ToArray();
        byte[] customization = label.ToArray();
        byte[] input = context.ToArray();
        try
        {
            var kmac = new KMac(strength, customization);
            kmac.Init(new KeyParameter(key));
            kmac.BlockUpdate(input, 0, input.Length);
            var output = new byte[outputLengthBits / 8];
            kmac.OutputFinal(output, 0, output.Length);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(customization);
            CryptographicOperations.ZeroMemory(input);
        }
    }
}
