// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;
using System.Collections.Generic;
using System.Linq;

#endregion

namespace Kdf108.Domain.Kdf.Modes;

public static class FunctionalExtensions
{
    // Monadic bind operation - applies a function to a value and returns the result
    public static TResult Bind<TSource, TResult>(this TSource source, Func<TSource, TResult> func) => func(source);

    // Pipeline operation - synonym for Bind, but more expressive for data transformations
    public static TResult Pipe<TSource, TResult>(this TSource source, Func<TSource, TResult> func) => func(source);

    // Apply a side effect function to a value and return the original value
    public static T Tee<T>(this T value, Action<T> action)
    {
        action(value);
        return value;
    }

    // Map operation for Option<T> pattern (simulated)
    public static TResult? Map<TSource, TResult>(this TSource? source, Func<TSource, TResult> func)
        where TSource : class
        where TResult : class =>
        source != null ? func(source) : null;

    // Safely execute a function that might throw and return a result/default value
    public static TResult? TryExecute<TSource, TResult>(this TSource source, Func<TSource, TResult> func)
        where TResult : class
    {
        try
        {
            return func(source);
        }
        catch
        {
            return null;
        }
    }

    // Transform an enumerable with a function and return the results (eager)
    public static IReadOnlyList<TResult> Transform<TSource, TResult>(
        this IEnumerable<TSource> source,
        Func<TSource, TResult> transform) =>
        source.Select(transform).ToList();
}
