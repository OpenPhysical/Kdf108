// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Domain.Kdf;

internal static class BitStringUtilities
{
    public static byte[] TruncateLeftmost(byte[] source, long lengthInBits)
    {
        int fullBytes = (int)(lengthInBits / 8);
        int extraBits = (int)(lengthInBits % 8);
        int outputBytes = fullBytes + (extraBits > 0 ? 1 : 0);

        if (source.Length < outputBytes)
        {
            throw new ArgumentException("Source does not contain the requested number of bits.", nameof(source));
        }

        byte[] output = new byte[outputBytes];
        Buffer.BlockCopy(source, 0, output, 0, outputBytes);

        if (extraBits > 0)
        {
            output[fullBytes] &= (byte)(0xFF << (8 - extraBits));
        }

        return output;
    }
}
