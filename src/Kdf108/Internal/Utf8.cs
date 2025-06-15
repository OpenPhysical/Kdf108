// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;
using System.Text;
using JetBrains.Annotations;

#endregion

namespace Kdf108.Internal;

public static class StringExtensions
{
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
