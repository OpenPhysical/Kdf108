// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Text;

namespace Kdf108.Domain.Kdf;

/// <summary>A KDF label with one canonical, lossless UTF-8 representation.</summary>
public sealed class KdfLabel
{
    private static readonly UTF8Encoding s_strictUtf8 = new(false, true);
    private readonly byte[] _encoded;

    private KdfLabel(string value, byte[] encoded)
    {
        Value = value;
        _encoded = encoded;
    }

    /// <summary>Gets the original label text without normalization.</summary>
    public string Value { get; }

    /// <summary>Creates a label and rejects text that cannot be encoded as strict UTF-8.</summary>
    public static KdfLabel FromString(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new KdfLabel(value, s_strictUtf8.GetBytes(value));
    }

    /// <summary>Returns a defensive copy of the UTF-8 encoding.</summary>
    public byte[] ToArray() => (byte[])_encoded.Clone();
}
