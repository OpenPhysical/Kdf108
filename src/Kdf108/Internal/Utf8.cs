// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Text;
using JetBrains.Annotations;

namespace Kdf108.Internal;

/// <summary>
/// Provides extension methods for string manipulation.
/// </summary>
public static class StringExtensions
{
    /// <summary>
    /// Converts a string to its UTF-8 byte representation.
    /// </summary>
    /// <param name="s">The string to convert.</param>
    /// <returns>A byte array containing the UTF-8 representation of the string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when the input string is null.</exception>
    [PublicAPI]
    public static byte[] ToUtf8(this string s)
    {
        if (s is null)
        {
            throw new ArgumentNullException(nameof(s));
        }

        return s.Length == 0 ? new byte[0] : Encoding.UTF8.GetBytes(s);
    }
}

