// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using Org.BouncyCastle.Crypto.Macs;

#endregion

namespace Kdf108.Infrastructure.Prf;

public static class HmacExtensions
{
    public static HMac ApplyData(this HMac hmac, byte[] data)
    {
        hmac.BlockUpdate(data, 0, data.Length);
        return hmac;
    }

    public static byte[] GetResult(this HMac hmac)
    {
        byte[] output = new byte[hmac.GetMacSize()];
        hmac.DoFinal(output, 0);
        return output;
    }
}
