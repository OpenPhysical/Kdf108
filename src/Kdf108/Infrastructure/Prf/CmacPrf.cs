// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Interfaces.Prf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Infrastructure.Prf;

/// <summary>
/// Implements a Cipher-based Message Authentication Code (CMAC) pseudorandom function.
/// </summary>
/// <remarks>
/// CMAC is a block cipher-based message authentication code algorithm that provides
/// both data origin authentication and data integrity. This implementation supports
/// various block ciphers through a factory pattern.
/// </remarks>
public sealed class CmacPrf : IPrf
{
    private readonly Func<IBlockCipher> _cipherFactory;
    private readonly int _keySizeBytes;

    /// <summary>
    /// Initializes a new instance of the <see cref="CmacPrf"/> class.
    /// </summary>
    /// <param name="cipherFactory">A factory function that creates block cipher instances.</param>
    /// <param name="outputSizeBits">The output size in bits for the PRF.</param>
    /// <param name="keySizeBytes">The one accepted key size in bytes.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="cipherFactory"/> is null.</exception>
    public CmacPrf(Func<IBlockCipher> cipherFactory, int outputSizeBits, int keySizeBytes)
    {
        _cipherFactory = cipherFactory ?? throw new ArgumentNullException(nameof(cipherFactory));
        OutputSizeBits = outputSizeBits;
        _keySizeBytes = keySizeBytes;
    }

    /// <inheritdoc/>
    public int OutputSizeBits { get; }

    /// <inheritdoc/>
    public byte[] Compute(byte[] key, byte[] data) =>
        CreateCmacInstance(key)
            .ApplyData(data)
            .GetResult();

    private CMac CreateCmacInstance(byte[] key)
    {
        CmacKey cmacKey = CmacKey.Create(key, _keySizeBytes, "CMAC");

        // Create a new block cipher instance
        IBlockCipher cipher = _cipherFactory();

        // Create and initialize CMAC
        CMac cmac = new(cipher);
        cmac.Init(new KeyParameter(cmacKey.ToArray()));

        return cmac;
    }
}
