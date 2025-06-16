// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;
using Kdf108.Domain.Interfaces.Prf;
using Kdf108.Domain.Kdf.Modes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace Kdf108.Infrastructure.Prf
{
    public sealed class CmacPrf : IPrf
    {
        private readonly Func<IBlockCipher> _cipherFactory;

        public CmacPrf(Func<IBlockCipher> cipherFactory, int outputSizeBits)
        {
            _cipherFactory = cipherFactory ?? throw new ArgumentNullException(nameof(cipherFactory));
            OutputSizeBits = outputSizeBits;
        }

        public int OutputSizeBits { get; }

        public byte[] Compute(byte[] key, byte[] data) =>
            CreateCmacInstance(key)
                .ApplyData(data)
                .GetResult();

        private CMac CreateCmacInstance(byte[] key)
        {
            // Create a new block cipher instance
            IBlockCipher? cipher = _cipherFactory();

            // Ensure key is appropriate for the cipher
            byte[] adjustedKey = AdjustKeyForCipher(key, cipher);

            // Create and initialize CMAC
            CMac cmac = new(cipher);
            cmac.Init(new KeyParameter(adjustedKey));

            return cmac;
        }

        private static byte[] AdjustKeyForCipher(byte[] key, IBlockCipher cipher)
        {
            // Special handling for TDES, which needs exactly 24 bytes
            if (cipher is DesEdeEngine && key.Length != 24)
            {
                byte[] adjustedKey = new byte[24];
                int copyLength = Math.Min(key.Length, 24);
                Buffer.BlockCopy(key, 0, adjustedKey, 0, copyLength);
                return adjustedKey;
            }

            return key;
        }
    }
}
