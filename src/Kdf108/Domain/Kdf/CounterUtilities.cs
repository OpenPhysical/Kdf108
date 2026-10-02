// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Domain.Kdf;

/// <summary>
/// Provides utility methods for counter operations in key derivation functions.
/// These utilities are compliant with NIST SP 800-108 specifications for counter-based KDFs.
/// </summary>
public static class CounterUtilities
{
    /// <summary>
    /// Creates a counter value encoded as a byte array with the specified length in bits.
    /// The counter is encoded in big-endian format as specified by NIST SP 800-108.
    /// </summary>
    /// <param name="value">The counter value to be encoded. Must be within the range of the specified bit length.</param>
    /// <param name="counterLengthBits">The length of the counter in bits, from 1 through 32.</param>
    /// <returns>
    /// A big-endian byte array of length <c>ceil(counterLengthBits / 8)</c>. For a non-octet
    /// counter, unused high-order bits in the first byte are zero.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the counter length is outside 1 through 32, or when the value exceeds the maximum for the specified bit length.
    /// </exception>
    public static byte[] CreateCounter(uint value, int counterLengthBits)
    {
        if (counterLengthBits <= 0 || counterLengthBits > 32)
        {
            throw new ArgumentException("Counter length must be between 1 and 32 bits", nameof(counterLengthBits));
        }

        uint maxValue = counterLengthBits == 32 ? uint.MaxValue : (1u << counterLengthBits) - 1;
        if (value > maxValue)
        {
            throw new ArgumentException($"Value {value} exceeds maximum {maxValue} for {counterLengthBits}-bit counter", nameof(value));
        }

        int bytes = (counterLengthBits + 7) / 8;
        byte[] counter = new byte[bytes];

        // Encode in big-endian format (most significant byte first)
        for (int j = bytes - 1, shift = 0; j >= 0; j--, shift += 8)
        {
            counter[j] = (byte)((value >> shift) & 0xFF);
        }

        return counter;
    }
}
