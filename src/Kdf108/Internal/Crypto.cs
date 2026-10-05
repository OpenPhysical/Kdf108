// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Internal;

/// <summary>The single mapping from <see cref="NistHashAlgorithm"/> to Bouncy Castle digests and sizes.</summary>
internal static class Hashes
{
    internal static IDigest CreateDigest(NistHashAlgorithm hash) => hash switch
    {
        NistHashAlgorithm.Sha1 => new Sha1Digest(),
        NistHashAlgorithm.Sha224 => new Sha224Digest(),
        NistHashAlgorithm.Sha256 => new Sha256Digest(),
        NistHashAlgorithm.Sha512_224 => new Sha512tDigest(224),
        NistHashAlgorithm.Sha512_256 => new Sha512tDigest(256),
        NistHashAlgorithm.Sha384 => new Sha384Digest(),
        NistHashAlgorithm.Sha512 => new Sha512Digest(),
        NistHashAlgorithm.Sha3_224 => new Sha3Digest(224),
        NistHashAlgorithm.Sha3_256 => new Sha3Digest(256),
        NistHashAlgorithm.Sha3_384 => new Sha3Digest(384),
        NistHashAlgorithm.Sha3_512 => new Sha3Digest(512),
        _ => throw new KdfParameterException($"Unknown hash function {hash}.", nameof(hash))
    };

    internal static int OutputBits(NistHashAlgorithm hash) => hash switch
    {
        NistHashAlgorithm.Sha1 => 160,
        NistHashAlgorithm.Sha224 or NistHashAlgorithm.Sha512_224 or NistHashAlgorithm.Sha3_224 => 224,
        NistHashAlgorithm.Sha256 or NistHashAlgorithm.Sha512_256 or NistHashAlgorithm.Sha3_256 => 256,
        NistHashAlgorithm.Sha384 or NistHashAlgorithm.Sha3_384 => 384,
        NistHashAlgorithm.Sha512 or NistHashAlgorithm.Sha3_512 => 512,
        _ => throw new KdfParameterException($"Unknown hash function {hash}.", nameof(hash))
    };

    /// <summary>The hash input block size, which is also the default HMAC salt length in SP 800-56C.</summary>
    internal static int BlockBytes(NistHashAlgorithm hash) => hash switch
    {
        NistHashAlgorithm.Sha1 or NistHashAlgorithm.Sha224 or NistHashAlgorithm.Sha256 => 64,
        NistHashAlgorithm.Sha512_224 or NistHashAlgorithm.Sha512_256 or NistHashAlgorithm.Sha384 or NistHashAlgorithm.Sha512 => 128,
        NistHashAlgorithm.Sha3_224 => 144,
        NistHashAlgorithm.Sha3_256 => 136,
        NistHashAlgorithm.Sha3_384 => 104,
        NistHashAlgorithm.Sha3_512 => 72,
        _ => throw new KdfParameterException($"Unknown hash function {hash}.", nameof(hash))
    };
}

/// <summary>Keyed MAC construction shared by SP 800-108, SP 800-56C, and key confirmation.</summary>
internal static class Macs
{
    /// <summary>Keys the PRF once. The returned MAC resets itself after each <c>DoFinal</c> and keeps its key.</summary>
    internal static IMac Create(Prf prf, ReadOnlySpan<byte> key)
    {
        IMac mac;
        if (prf.Hash is { } hash)
        {
            mac = new HMac(Hashes.CreateDigest(hash));
        }
        else
        {
            if (key.Length * 8 != prf.AesKeyBits)
                throw new KdfParameterException($"{prf} requires a {prf.AesKeyBits}-bit key; got {key.Length * 8} bits.", nameof(key));
            mac = new CMac(new AesEngine());
        }

        mac.Init(new KeyParameter(key));
        return mac;
    }

    internal static byte[] Compute(Prf prf, ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        IMac mac = Create(prf, key);
        mac.BlockUpdate(data);
        var output = new byte[mac.GetMacSize()];
        mac.DoFinal(output);
        return output;
    }

    /// <summary>
    /// KMAC128 or KMAC256 (SP 800-185). KMAC binds L into its input through right_encode(L), so
    /// truncating a longer output is not equivalent; callers must pass the exact, octet-aligned L.
    /// </summary>
    internal static byte[] Kmac(int strength, ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> customization, long outputBits)
    {
        if ((outputBits & 7) != 0)
            throw new KdfParameterException("KMAC output lengths must be a whole number of bytes.", nameof(outputBits));
        var kmac = new KMac(strength, customization.ToArray());
        kmac.Init(new KeyParameter(key));
        kmac.BlockUpdate(data);
        var output = new byte[checked((int)(outputBits / 8))];
        kmac.OutputFinal(output, 0, output.Length);
        return output;
    }
}

internal static class Bits
{
    /// <summary>Keeps the leftmost <paramref name="bitLength"/> bits, clearing the unused low bits of the last byte.</summary>
    internal static void MaskTail(Span<byte> output, long bitLength)
    {
        int remainder = (int)(bitLength & 7);
        if (remainder != 0)
            output[^1] &= (byte)(0xFF << (8 - remainder));
    }
}
