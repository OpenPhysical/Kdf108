// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Test.Logging;

/// <summary>
/// Exception that includes log context for test failures.
/// This allows test logs to propagate structurally with exceptions without emitting to stdout.
/// </summary>
public class ExceptionWithLogContext : Exception
{
    /// <summary>
    /// Gets or sets the log context captured during the test.
    /// </summary>
    public string? LogContext { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ExceptionWithLogContext"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public ExceptionWithLogContext(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>
    /// Returns a string representation of the current exception including log context.
    /// </summary>
    /// <returns>A string that represents the current exception.</returns>
    public override string ToString()
    {
        var baseString = base.ToString();
        
        if (string.IsNullOrEmpty(LogContext))
        {
            return baseString;
        }
        
        return baseString + Environment.NewLine + 
               "=== Log Context ===" + Environment.NewLine + 
               LogContext;
    }
}