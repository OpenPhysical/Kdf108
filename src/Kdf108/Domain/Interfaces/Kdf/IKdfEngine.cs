// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using Kdf108.Domain.Kdf;

#endregion

namespace Kdf108.Domain.Interfaces.Kdf
{
    /// <summary>
    /// Represents a key derivation function (KDF) engine interface for generating
    /// cryptographic keys from an established key derivation key (KDK).
    /// </summary>
    public interface IKdfEngine
    {
        /// <summary>
        /// Derives a key based on the input key derivation key (KDK) and the specified options.
        /// </summary>
        /// <param name="mode">The key derivation function (KDF) mode to be used.</param>
        /// <param name="kdk">The key derivation key (KDK) as a byte array.</param>
        /// <param name="label">A string label used in the derivation process.</param.
        /// <param name="context">A byte array representing the context information for the derivation process.</param>
        /// <param name="outputLengthInBits">The desired output length in bits for the derived key.</param>
        /// <param name="options">The options that dictate specific behaviors or configurations of the KDF.</param>
        /// <returns>A byte array representing the derived key.</returns>
        byte[] Derive(
            KdfMode mode,
            byte[] kdk,
            string label,
            byte[] context,
            long outputLengthInBits,
            KdfOptions options);
    }
}
