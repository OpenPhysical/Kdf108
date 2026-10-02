// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

namespace Kdf108.Internal
{
#if NET5_0_OR_GREATER
    using System;
#endif

    /// <summary>
    /// Provides utility methods for converting data between hexadecimal string
    /// representations and byte arrays.
    /// </summary>
    /// <remarks>
    /// This utility class offers two static methods:
    /// <c>FromHexString</c> and <c>ToHexString</c>. These methods facilitate
    /// encoding and decoding operations that convert between byte arrays
    /// and their corresponding hexadecimal representations.
    /// </remarks>
    public static class ConvertCompat
    {
#if NET5_0_OR_GREATER

        /// <summary>
        /// Converts a hexadecimal string to a byte array.
        /// </summary>
        /// <param name="hex">The hexadecimal string to convert.</param>
        /// <returns>A byte array representing the hexadecimal string.</returns>
        public static byte[] FromHexString(string hex) => Convert.FromHexString(hex);
        
        /// <summary>
        /// Converts a byte array to a hexadecimal string.
        /// </summary>
        /// <param name="data">The byte array to convert.</param>
        /// <returns>A hexadecimal string representation of the byte array.</returns>
        public static string ToHexString(byte[] data) => Convert.ToHexString(data);
#else
    public static byte[] FromHexString(string hex) => Hex.Decode(hex);

    public static string ToHexString(byte[] data) => Hex.ToHexString(data);
#endif
    }
}
