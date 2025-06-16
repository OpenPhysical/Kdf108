// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using Org.BouncyCastle.Utilities.Encoders;

#endregion

namespace Kdf108.Internal
    /// <summary>
    ///     Provides utility methods for converting data between hexadecimal string
    ///     representations and byte arrays.
    /// </summary>
    /// <remarks>
    ///     This utility class offers two static methods:
    ///     <c>FromHexString</c> and <c>ToHexString</c>. These methods specifically
    ///     facilitate encoding and decoding operations that convert between byte arrays
    ///     and their corresponding hexadecimal representations. The class leverages
    ///     third-party utilities to handle the conversions with precision.
    ///     Purpose-built for scenarios requiring the manipulation of cryptographic
    ///     and binary data in hexadecimal format, the methods ensure efficient and
    ///     reliable data transformations.
    /// </remarks>
{
#if NET5_0_OR_GREATER
    using System;
#endif

    public static class ConvertCompat
    {
#if NET5_0_OR_GREATER

        public static byte[] FromHexString(string hex) => Convert.FromHexString(hex);
        public static string ToHexString(byte[] data) => Convert.ToHexString(data);
#else
    public static byte[] FromHexString(string hex) => Hex.Decode(hex);

    public static string ToHexString(byte[] data) => Hex.ToHexString(data);
#endif
    }
}
