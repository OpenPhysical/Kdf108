// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;
using System.Collections.Generic;
using Kdf108.Domain.Interfaces.Prf;
using Kdf108.Domain.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;

#endregion

namespace Kdf108.Infrastructure.Prf;

public static class PrfFactory
{
    private static readonly Dictionary<PrfType, Func<IPrf>> s_prfFactories =
        new()
        {
            // HMAC PRFs
            [PrfType.HmacSha1] = () => new HmacPrf(() => new Sha1Digest()),
            [PrfType.HmacSha224] = () => new HmacPrf(() => new Sha224Digest()),
            [PrfType.HmacSha256] = () => new HmacPrf(() => new Sha256Digest()),
            [PrfType.HmacSha384] = () => new HmacPrf(() => new Sha384Digest()),
            [PrfType.HmacSha512] = () => new HmacPrf(() => new Sha512Digest()),

            // CMAC PRFs
            [PrfType.CmacAes128] = () => new CmacPrf(() => new AesEngine(), 128),
            [PrfType.CmacAes192] = () => new CmacPrf(() => new AesEngine(), 128),
            [PrfType.CmacAes256] = () => new CmacPrf(() => new AesEngine(), 128),
            [PrfType.CmacTdes3] = () => new CmacPrf(() => new DesEdeEngine(), 64)
        };

    public static IPrf Create(PrfType type) =>
        s_prfFactories.TryGetValue(type, out Func<IPrf>? factory)
            ? factory()
            : throw new NotSupportedException($"PRF type '{type}' is not supported.");
}
