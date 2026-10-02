// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Linq;
using Microsoft.Extensions.Logging.Testing;

namespace Kdf108.Test.Logging;

/// <summary>
/// Extension methods for test logging integration.
/// </summary>
public static class TestLoggingExtensions
{
    /// <summary>
    /// Attaches logs from a fake logger to an exception.
    /// This method always returns false, allowing it to be used in exception filters.
    /// </summary>
    /// <param name="exception">The exception that occurred.</param>
    /// <param name="logger">The fake logger containing logs.</param>
    /// <returns>Always returns false.</returns>
    public static bool AttachLogs<T>(this Exception exception, FakeLogger<T> logger)
    {
        var logs = string.Join(Environment.NewLine,
            logger.Collector.GetSnapshot().Select(log => 
                $"[{log.Level}] {typeof(T).Name}: {log.Message}"));
        
        throw new ExceptionWithLogContext($"Test failed: {exception.Message}", exception)
        {
            LogContext = logs
        };
    }

    /// <summary>
    /// Gets formatted log output from a fake logger.
    /// </summary>
    /// <param name="logger">The fake logger.</param>
    /// <returns>Formatted log output.</returns>
    public static string GetFormattedLogs<T>(this FakeLogger<T> logger)
    {
        return string.Join(Environment.NewLine,
            logger.Collector.GetSnapshot().Select(log => 
                $"[{log.Level}] {typeof(T).Name}: {log.Message}"));
    }
}