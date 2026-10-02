// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using Kdf108.Domain.Interfaces.Prf;
using Kdf108.Domain.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;

namespace Kdf108.Infrastructure.Prf;

/// <summary>
/// Provides the functionality to create instances of pseudorandom functions (PRFs)
/// based on the specified <see cref="PrfType"/>.
/// </summary>
/// <remarks>
/// The <see cref="PrfFactory"/> supports a variety of PRF types that are
/// registered through the factory. Attempting to create an unsupported PRF type
/// will result in a <see cref="NotSupportedException"/> being thrown.
/// </remarks>
/// <example>
/// To create a PRF instance, use the <see cref="Create"/> method with a
/// valid <see cref="PrfType"/>. This allows integration of the PRF with
/// various KDF (Key Derivation Function) modes.
/// </example>
public static class PrfFactory
{
    /// <summary>
    /// A static dictionary that maps pseudorandom function (PRF) types to factory methods for creating their corresponding implementations.
    /// </summary>
    /// <remarks>
    /// This dictionary is used to centralize the instantiation of PRF implementations.
    /// Each key is a value from the <see cref="PrfType"/> enumeration, and the associated value is a factory method
    /// that produces an instance of the <see cref="IPrf"/> interface. Implementations support HMAC-based and CMAC-based PRFs.
    /// </remarks>
    private static readonly Dictionary<PrfType, Func<IPrf>> s_prfFactories =
        new()
        {
            // HMAC PRFs
            [PrfType.HmacSha1] = static () => new HmacPrf(static () => new Sha1Digest()),
            [PrfType.HmacSha224] = static () => new HmacPrf(static () => new Sha224Digest()),
            [PrfType.HmacSha256] = static () => new HmacPrf(static () => new Sha256Digest()),
            [PrfType.HmacSha384] = static () => new HmacPrf(static () => new Sha384Digest()),
            [PrfType.HmacSha512] = static () => new HmacPrf(static () => new Sha512Digest()),
            [PrfType.HmacSha512_224] = static () => new HmacPrf(static () => new Sha512tDigest(224)),
            [PrfType.HmacSha512_256] = static () => new HmacPrf(static () => new Sha512tDigest(256)),
            [PrfType.HmacSha3_224] = static () => new HmacPrf(static () => new Sha3Digest(224)),
            [PrfType.HmacSha3_256] = static () => new HmacPrf(static () => new Sha3Digest(256)),
            [PrfType.HmacSha3_384] = static () => new HmacPrf(static () => new Sha3Digest(384)),
            [PrfType.HmacSha3_512] = static () => new HmacPrf(static () => new Sha3Digest(512)),

            // CMAC PRFs
            [PrfType.CmacAes128] = static () => new CmacPrf(static () => new AesEngine(), 128, 16),
            [PrfType.CmacAes192] = static () => new CmacPrf(static () => new AesEngine(), 128, 24),
            [PrfType.CmacAes256] = static () => new CmacPrf(static () => new AesEngine(), 128, 32),
            [PrfType.CmacTdes3] = static () => new CmacPrf(static () => new DesEdeEngine(), 64, 24),
            [PrfType.CmacTdes2] = static () => new CmacTdes2Prf()
        };

    /// <summary>
    /// Creates an instance of an implementation of the IPrf interface based on the specified PRF type.
    /// </summary>
    /// <param name="type">The PRF type to create.</param>
    /// <returns>An instance of IPrf corresponding to the specified PRF type.</returns>
    /// <exception cref="NotSupportedException">Thrown if the specified PRF type is not supported.</exception>
    public static IPrf Create(PrfType type) =>
        s_prfFactories.TryGetValue(type, out Func<IPrf>? factory)
            ? factory()
            : throw new NotSupportedException($"PRF type '{type}' is not supported.");
}
