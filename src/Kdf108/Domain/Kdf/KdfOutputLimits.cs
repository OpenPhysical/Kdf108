// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Domain.Kdf;

internal static class KdfOutputLimits
{
    public static (long Repetitions, int BufferBytes) Validate(
        long outputLengthInBits,
        int outputSizeBits,
        int counterLengthBits,
        bool useCounter)
    {
        if (outputLengthInBits <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLengthInBits));
        if (outputLengthInBits > uint.MaxValue)
            throw new ArgumentException("Output length cannot be encoded in the 32-bit [L] field.", nameof(outputLengthInBits));
        if (outputSizeBits <= 0 || (outputSizeBits & 7) != 0)
            throw new ArgumentOutOfRangeException(nameof(outputSizeBits));
        if (counterLengthBits is < 1 or > 32)
            throw new ArgumentOutOfRangeException(nameof(counterLengthBits));

        long repetitions = checked((outputLengthInBits + outputSizeBits - 1) / outputSizeBits);
        if (useCounter)
        {
            long maximum = (1L << counterLengthBits) - 1;
            if (repetitions > maximum)
                throw new ArgumentException($"Too much output requested, exceeds the {counterLengthBits}-bit counter limit.", nameof(outputLengthInBits));
        }

        long bufferBytes = checked(repetitions * (outputSizeBits / 8L));
        if (bufferBytes > Array.MaxLength)
            throw new ArgumentException("Too much output requested, exceeds managed-array limits.", nameof(outputLengthInBits));

        return (repetitions, checked((int)bufferBytes));
    }
}
