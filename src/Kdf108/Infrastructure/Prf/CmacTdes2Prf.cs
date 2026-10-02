// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Interfaces.Prf;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Infrastructure.Prf;

/// <summary>
/// CMAC PRF implementation specifically for TDES2 (2-key Triple DES).
/// TDES2 uses a 16-byte key where K3 = K1 (K1|K2|K1 pattern).
/// </summary>
public sealed class CmacTdes2Prf : IPrf
{
    /// <inheritdoc/>
    public int OutputSizeBits => 64;

    /// <inheritdoc/>
    public byte[] Compute(byte[] key, byte[] data)
    {
        // Convert 16-byte TDES2 key to 24-byte TDES3 key format (K1|K2|K1)
        CmacKey cmacKey = CmacKey.Create(key, 16, "CMAC-TDES2");
        byte[] tdes3Key = ConvertTdes2KeyToTdes3(cmacKey.ToArray());
        
        // Create CMAC with TDES engine
        var cipher = new DesEdeEngine();
        var cmac = new CMac(cipher);
        cmac.Init(new KeyParameter(tdes3Key));
        
        // Process the data
        cmac.BlockUpdate(data, 0, data.Length);
        
        // Get the result
        byte[] result = new byte[cmac.GetMacSize()];
        cmac.DoFinal(result, 0);
        
        return result;
    }

    private static byte[] ConvertTdes2KeyToTdes3(byte[] tdes2Key)
    {
        // Create 24-byte key in K1|K2|K1 format
        byte[] tdes3Key = new byte[24];
        
        // K1 (first 8 bytes)
        Buffer.BlockCopy(tdes2Key, 0, tdes3Key, 0, 8);
        
        // K2 (next 8 bytes)
        Buffer.BlockCopy(tdes2Key, 8, tdes3Key, 8, 8);
        
        // K3 = K1 (repeat first 8 bytes)
        Buffer.BlockCopy(tdes2Key, 0, tdes3Key, 16, 8);
        
        return tdes3Key;
    }
}
