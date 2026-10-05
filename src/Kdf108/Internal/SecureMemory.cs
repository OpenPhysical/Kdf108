// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Internal;

/// <summary>Clears temporary byte buffers before they become unreachable.</summary>
internal static class SecureMemory
{
    /// <summary>Overwrites the complete buffer with zeroes.</summary>
    internal static void Clear(byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        Array.Clear(buffer, 0, buffer.Length);
    }
}
