// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Infrastructure.Prf;

internal sealed class CmacKey
{
    private readonly byte[] _bytes;

    private CmacKey(byte[] bytes) => _bytes = bytes;

    public static CmacKey Create(byte[] key, int expectedSizeBytes, string algorithmName)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != expectedSizeBytes)
        {
            throw new ArgumentException(
                $"{algorithmName} key must be exactly {expectedSizeBytes} bytes.", nameof(key));
        }

        return new CmacKey((byte[])key.Clone());
    }

    public byte[] ToArray() => (byte[])_bytes.Clone();
}
