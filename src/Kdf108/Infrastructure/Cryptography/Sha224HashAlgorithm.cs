// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;

namespace Kdf108.Infrastructure.Cryptography;

/// <summary>
/// Provides a .NET HashAlgorithm wrapper for the SHA-224 hash function using BouncyCastle.
/// SHA-224 is defined in FIPS 180-4 and produces a 224-bit (28-byte) hash value.
/// </summary>
/// <remarks>
/// This implementation wraps the BouncyCastle SHA-224 digest to provide compatibility
/// with the standard .NET HashAlgorithm base class, enabling its use in scenarios
/// that require the standard .NET cryptographic interfaces.
/// </remarks>
public sealed class Sha224HashAlgorithm : HashAlgorithm
{
    private readonly Sha224Digest _digest;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sha224HashAlgorithm"/> class.
    /// </summary>
    public Sha224HashAlgorithm()
    {
        _digest = new Sha224Digest();
        HashSizeValue = 224; // 28 bytes * 8 bits/byte = 224 bits
    }

    /// <summary>
    /// Routes data written to the object into the SHA-224 hash algorithm for computing the hash.
    /// </summary>
    /// <param name="array">The input data to hash.</param>
    /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
    /// <param name="cbSize">The number of bytes in the array to use as data.</param>
    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        _digest.BlockUpdate(array, ibStart, cbSize);
    }

    /// <summary>
    /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
    /// </summary>
    /// <returns>The computed hash value as a byte array.</returns>
    protected override byte[] HashFinal()
    {
        var hash = new byte[_digest.GetDigestSize()];
        _digest.DoFinal(hash, 0);
        return hash;
    }

    /// <summary>
    /// Initializes an implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    public override void Initialize()
    {
        _digest.Reset();
    }

    /// <summary>
    /// Releases the unmanaged resources used by the <see cref="Sha224HashAlgorithm"/> and optionally releases the managed resources.
    /// </summary>
    /// <param name="disposing">
    /// <see langword="true"/> to release both managed and unmanaged resources; 
    /// <see langword="false"/> to release only unmanaged resources.
    /// </param>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _digest.Reset();
        }
        base.Dispose(disposing);
    }
}