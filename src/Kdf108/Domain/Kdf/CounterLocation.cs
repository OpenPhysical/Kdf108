// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

namespace Kdf108.Domain.Kdf
{
    /// <summary>
    ///     Specifies the position of the counter in the KDF input
    /// </summary>
    public enum CounterLocation
    {
        /// <summary>
        ///     Counter appears before the fixed input data
        /// </summary>
        BeforeFixed,

        /// <summary>
        ///     Counter appears after the fixed input data
        /// </summary>
        AfterFixed,

        /// <summary>
        ///     Counter appears in the middle of the fixed input data
        /// </summary>
        MiddleFixed
    }
}
