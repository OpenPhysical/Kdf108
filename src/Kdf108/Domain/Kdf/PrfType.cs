// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

namespace Kdf108.Domain.Kdf
{
    /// <summary>
    ///     Enumeration of supported pseudorandom function types for key derivation
    /// </summary>
    public enum PrfType
    {
        // HMAC PRFs
        HmacSha1,
        HmacSha224,
        HmacSha256,
        HmacSha384,
        HmacSha512,

        // CMAC PRFs
        CmacAes128,
        CmacAes192,
        CmacAes256,
        CmacTdes3
    }
}
