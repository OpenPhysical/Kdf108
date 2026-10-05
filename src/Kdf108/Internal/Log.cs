// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Microsoft.Extensions.Logging;

namespace Kdf108.Internal;

/// <summary>
/// Source-generated log messages for the services. They carry algorithm names, lengths, and
/// rejection reasons only. Keys, shared secrets, and derived output are never logged.
/// </summary>
internal static partial class Log
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Debug, Message = "{Standard} {Operation} produced {OutputBits} bits")]
    internal static partial void Completed(ILogger logger, string standard, string operation, long outputBits);

    [LoggerMessage(EventId = 2, Level = LogLevel.Warning, Message = "{Operation} rejected: {Reason}")]
    private static partial void RejectedCore(ILogger logger, string operation, string reason);

    [LoggerMessage(EventId = 3, Level = LogLevel.Warning, Message = "Key confirmation failed: the received {Mac} tag does not match")]
    internal static partial void TagMismatch(ILogger logger, string mac);

    /// <summary>
    /// Logs a rejection and returns <see langword="false"/>, for use as an exception filter
    /// (<c>catch (Kdf108Exception e) when (Log.Rejected(...))</c>) that logs without catching.
    /// </summary>
    internal static bool Rejected(ILogger logger, string operation, Exception exception)
    {
        RejectedCore(logger, operation, exception.Message);
        return false;
    }
}
