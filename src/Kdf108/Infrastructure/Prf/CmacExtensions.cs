// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using Org.BouncyCastle.Crypto.Macs;

#endregion

namespace Kdf108.Infrastructure.Prf
{
    /// <summary>
    ///     Provides extension methods for the CMac class from the BouncyCastle encryption library.
    /// </summary>
    public static class CmacExtensions
    {
        /// <summary>
        ///     Adds the specified data to the CMAC instance for calculation.
        /// </summary>
        /// <param name="cmac">The CMAC instance to which the data will be applied.</param>
        /// <param name="data">The data to be processed by the CMAC instance.</param>
        /// <returns>The updated CMAC instance.</returns>
        public static CMac ApplyData(this CMac cmac, byte[] data)
        {
            cmac.BlockUpdate(data, 0, data.Length);
            return cmac;
        }

        /// <summary>
        ///     Computes the final CMAC result and returns the output as a byte array.
        /// </summary>
        /// <param name="cmac">The CMAC instance from which to compute the result.</param>
        /// <returns>The computed CMAC result as a byte array.</returns>
        public static byte[] GetResult(this CMac cmac)
        {
            byte[] output = new byte[cmac.GetMacSize()];
            cmac.DoFinal(output, 0);
            return output;
        }
    }
}
