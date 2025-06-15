// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using Org.BouncyCastle.Crypto.Macs;

#endregion

namespace Kdf108.Infrastructure.Prf;

/// <summary>
/// Provides extension methods for working with HMac instances from the BouncyCastle library.
/// </summary>
public static class HmacExtensions
{
    /// <summary>
    /// Updates the provided HMAC instance with the specified data and returns the updated instance.
    /// </summary>
    /// <param name="hmac">The HMAC instance to which the data will be applied.</param>
    /// <param name="data">The byte array data to update the HMAC with.</param>
    /// <returns>The updated HMAC instance after applying the data.</returns>
    public static HMac ApplyData(this HMac hmac, byte[] data)
    {
        hmac.BlockUpdate(data, 0, data.Length);
        return hmac;
    }

    /// <summary>
    /// Finalizes the HMAC computation and retrieves the generated MAC (Message Authentication Code) as a byte array.
    /// </summary>
    /// <param name="hmac">The HMac instance on which the final computation is performed.</param>
    /// <returns>A byte array containing the generated MAC value.</returns>
    public static byte[] GetResult(this HMac hmac)
    {
        byte[] output = new byte[hmac.GetMacSize()];
        hmac.DoFinal(output, 0);
        return output;
    }
}
