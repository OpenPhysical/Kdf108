// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;
using Kdf108.Domain.Interfaces.Prf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace Kdf108.Infrastructure.Prf
{
    /// <summary>
    /// Provides an implementation of a Pseudorandom Function (PRF) using HMAC (Hashed Message Authentication Code).
    /// </summary>
    public sealed class HmacPrf : IPrf
    {
        /// <summary>
        /// Delegate function responsible for producing instances of <see cref="IDigest"/>.
        /// Used to create hash function implementations required by the HMAC algorithm.
        /// </summary>
        private readonly Func<IDigest> _digestFactory;

        /// <summary>
        /// A pseudorandom function (PRF) implementation based on HMAC (Hash-based Message Authentication Code).
        /// </summary>
        public HmacPrf(Func<IDigest> digestFactory) =>
            _digestFactory = digestFactory ?? throw new ArgumentNullException(nameof(digestFactory));

        /// <summary>
        /// Gets the output size of the pseudorandom function in bits.
        /// </summary>
        /// <remarks>
        /// For HMAC-based implementations, the output size is determined by the size
        /// of the underlying hash function used. For example, for SHA-256, the output
        /// size will be 256 bits.
        /// </remarks>
        public int OutputSizeBits => _digestFactory().GetDigestSize() * 8;

        /// <summary>
        /// Computes a pseudorandom value using the specified key and data, based on the provided HMAC digest algorithm.
        /// </summary>
        /// <param name="key">The cryptographic key used for the HMAC computation.</param>
        /// <param name="data">The input data to be processed with the key.</param>
        /// <returns>A byte array containing the computed pseudorandom value.</returns>
        public byte[] Compute(byte[] key, byte[] data) =>
            CreateHmacInstance(key)
                .ApplyData(data)
                .GetResult();

        /// <summary>
        /// Creates an instance of the HMac class configured with the provided key.
        /// </summary>
        /// <param name="key">The secret key to initialize the HMAC instance.</param>
        /// <returns>An initialized HMac instance using the specified key.</returns>
        private HMac CreateHmacInstance(byte[] key)
        {
            IDigest? digest = _digestFactory();
            HMac hmac = new(digest);
            hmac.Init(new KeyParameter(key));
            return hmac;
        }
    }
}
