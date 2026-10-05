// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108;

/// <summary>The approved hash functions used across SP 800-108, SP 800-56A, and SP 800-56C.</summary>
public enum NistHashAlgorithm
{
    /// <summary>SHA-1 (160-bit output). Permitted for key derivation, not for digital signatures.</summary>
    Sha1,
    /// <summary>SHA-224.</summary>
    Sha224,
    /// <summary>SHA-256.</summary>
    Sha256,
    /// <summary>SHA-512/224.</summary>
    Sha512_224,
    /// <summary>SHA-512/256.</summary>
    Sha512_256,
    /// <summary>SHA-384.</summary>
    Sha384,
    /// <summary>SHA-512.</summary>
    Sha512,
    /// <summary>SHA3-224.</summary>
    Sha3_224,
    /// <summary>SHA3-256.</summary>
    Sha3_256,
    /// <summary>SHA3-384.</summary>
    Sha3_384,
    /// <summary>SHA3-512.</summary>
    Sha3_512
}

/// <summary>A target security strength from SP 800-56A Rev. 3 and SP 800-57.</summary>
public readonly record struct SecurityStrength
{
    private SecurityStrength(int bits) => Bits = bits;

    /// <summary>The security strength in bits.</summary>
    public int Bits { get; }

    /// <summary>112-bit security strength.</summary>
    public static SecurityStrength Bits112 { get; } = new(112);
    /// <summary>128-bit security strength.</summary>
    public static SecurityStrength Bits128 { get; } = new(128);
    /// <summary>152-bit security strength.</summary>
    public static SecurityStrength Bits152 { get; } = new(152);
    /// <summary>176-bit security strength.</summary>
    public static SecurityStrength Bits176 { get; } = new(176);
    /// <summary>192-bit security strength.</summary>
    public static SecurityStrength Bits192 { get; } = new(192);
    /// <summary>200-bit security strength.</summary>
    public static SecurityStrength Bits200 { get; } = new(200);
    /// <summary>256-bit security strength.</summary>
    public static SecurityStrength Bits256 { get; } = new(256);

    /// <inheritdoc />
    public override string ToString() => $"{Bits}-bit";
}

/// <summary>A positive length in bits. Every output, tag, and MAC length in this library is a <see cref="BitLength"/>.</summary>
public readonly record struct BitLength
{
    private BitLength(long bits) => Bits = bits;

    /// <summary>The length in bits.</summary>
    public long Bits { get; }

    /// <summary>The number of bytes needed to hold <see cref="Bits"/> bits.</summary>
    public int ByteLength => checked((int)((Bits + 7) / 8));

    /// <summary>Creates a bit length.</summary>
    /// <exception cref="KdfParameterException"><paramref name="bits"/> is not positive.</exception>
    public static BitLength Create(long bits) =>
        bits > 0 ? new BitLength(bits) : throw new KdfParameterException("A bit length must be positive.", nameof(bits));

    /// <summary>Creates a bit length from a whole number of bytes.</summary>
    /// <exception cref="KdfParameterException"><paramref name="bytes"/> is not positive.</exception>
    public static BitLength FromBytes(int bytes) => Create(bytes * 8L);

    /// <inheritdoc />
    public override string ToString() => $"{Bits} bits";
}

/// <summary>
/// A pseudorandom function for SP 800-108 iterative key derivation: HMAC with an approved hash, or AES-CMAC.
/// </summary>
public sealed record Prf
{
    private Prf(NistHashAlgorithm? hash, int aesKeyBits)
    {
        Hash = hash;
        AesKeyBits = aesKeyBits;
    }

    /// <summary>The HMAC hash function, or <see langword="null"/> for AES-CMAC.</summary>
    public NistHashAlgorithm? Hash { get; }

    /// <summary>The AES key size for AES-CMAC, or 0 for HMAC.</summary>
    public int AesKeyBits { get; }

    /// <summary><see langword="true"/> for AES-CMAC.</summary>
    public bool IsCmac => Hash is null;

    /// <summary>The PRF output length h, in bits.</summary>
    public int OutputBits => Hash is { } hash ? Internal.Hashes.OutputBits(hash) : 128;

    /// <summary>HMAC with the given hash function.</summary>
    public static Prf Hmac(NistHashAlgorithm hash) =>
        Enum.IsDefined(hash) ? new Prf(hash, 0) : throw new KdfParameterException($"Unknown hash function {hash}.", nameof(hash));

    /// <summary>AES-CMAC with a 128-, 192-, or 256-bit key.</summary>
    public static Prf AesCmac(int keyBits) =>
        keyBits is 128 or 192 or 256
            ? new Prf(null, keyBits)
            : throw new KdfParameterException("AES-CMAC requires a 128, 192, or 256-bit key.", nameof(keyBits));

    /// <inheritdoc />
    public override string ToString() => Hash is { } hash ? $"HMAC-{hash}" : $"AES-{AesKeyBits}-CMAC";
}
