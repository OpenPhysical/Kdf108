// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;

namespace Kdf108.Domain.Kdf.Modes;

/// <summary>
/// Provides functional programming extension methods for fluent and composable operations.
/// </summary>
/// <remarks>
/// This class contains extension methods that enable functional programming patterns
/// such as pipelining, monadic operations, and safe transformations.
/// </remarks>
public static class FunctionalExtensions
{
    /// <summary>
    /// Applies a monadic bind operation by executing a function on the source value.
    /// </summary>
    /// <typeparam name="TSource">The type of the source value.</typeparam>
    /// <typeparam name="TResult">The type of the result value.</typeparam>
    /// <param name="source">The source value to transform.</param>
    /// <param name="func">The function to apply to the source value.</param>
    /// <returns>The result of applying the function to the source value.</returns>
    public static TResult Bind<TSource, TResult>(this TSource source, Func<TSource, TResult> func) => func(source);

    /// <summary>
    /// Pipes a value through a transformation function in a fluent manner.
    /// </summary>
    /// <typeparam name="TSource">The type of the source value.</typeparam>
    /// <typeparam name="TResult">The type of the result value.</typeparam>
    /// <param name="source">The source value to transform.</param>
    /// <param name="func">The transformation function to apply.</param>
    /// <returns>The result of the transformation.</returns>
    /// <remarks>
    /// This method is semantically identical to Bind but provides a more expressive name
    /// for pipeline-style data transformations.
    /// </remarks>
    public static TResult Pipe<TSource, TResult>(this TSource source, Func<TSource, TResult> func) => func(source);

    /// <summary>
    /// Executes a side effect action on a value and returns the original value unchanged.
    /// </summary>
    /// <typeparam name="T">The type of the value.</typeparam>
    /// <param name="value">The value to pass to the action.</param>
    /// <param name="action">The side effect action to execute.</param>
    /// <returns>The original value unchanged.</returns>
    /// <remarks>
    /// This method is useful for inserting logging, debugging, or other side effects
    /// into a functional pipeline without breaking the chain.
    /// </remarks>
    public static T Tee<T>(this T value, Action<T> action)
    {
        action(value);
        return value;
    }

    /// <summary>
    /// Maps a nullable reference type through a transformation function, propagating null values.
    /// </summary>
    /// <typeparam name="TSource">The type of the source value.</typeparam>
    /// <typeparam name="TResult">The type of the result value.</typeparam>
    /// <param name="source">The nullable source value to transform.</param>
    /// <param name="func">The transformation function to apply if the source is not null.</param>
    /// <returns>The transformed value if the source was not null; otherwise, null.</returns>
    /// <remarks>
    /// This method implements the Option/Maybe pattern for nullable reference types,
    /// allowing safe transformation of potentially null values.
    /// </remarks>
    public static TResult? Map<TSource, TResult>(this TSource? source, Func<TSource, TResult> func)
        where TSource : class
        where TResult : class =>
        source != null ? func(source) : null;

    /// <summary>
    /// Safely executes a function that might throw exceptions, returning null on failure.
    /// </summary>
    /// <typeparam name="TSource">The type of the source value.</typeparam>
    /// <typeparam name="TResult">The type of the result value.</typeparam>
    /// <param name="source">The source value to pass to the function.</param>
    /// <param name="func">The function to execute that might throw exceptions.</param>
    /// <returns>The result of the function if successful; otherwise, null.</returns>
    /// <remarks>
    /// This method provides a way to handle potentially failing operations without
    /// explicit exception handling in the calling code. Use with caution as it
    /// suppresses all exceptions.
    /// </remarks>
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

    /// <summary>
    /// Eagerly transforms all elements in a sequence using the specified transformation function.
    /// </summary>
    /// <typeparam name="TSource">The type of the source elements.</typeparam>
    /// <typeparam name="TResult">The type of the result elements.</typeparam>
    /// <param name="source">The source sequence to transform.</param>
    /// <param name="transform">The transformation function to apply to each element.</param>
    /// <returns>A read-only list containing the transformed elements.</returns>
    /// <remarks>
    /// Unlike LINQ's Select method, this method eagerly evaluates the transformation
    /// and returns a materialized list, which can be useful when the transformation
    /// needs to be completed before proceeding.
    /// </remarks>
    public static IReadOnlyList<TResult> Transform<TSource, TResult>(
        this IEnumerable<TSource> source,
        Func<TSource, TResult> transform) =>
        source.Select(transform).ToList();
}

