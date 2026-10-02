// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Exceptions;

/// <summary>
/// Base exception for all Kdf108 library exceptions.
/// </summary>
public class Kdf108Exception : Exception
{
    /// <summary>
    /// Gets the error code associated with this exception.
    /// </summary>
    public string ErrorCode { get; }

    /// <summary>
    /// Gets additional context information about the error.
    /// </summary>
    public string? Context { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Kdf108Exception"/> class.
    /// </summary>
    public Kdf108Exception() : base("An error occurred in the Kdf108 library.")
    {
        ErrorCode = "KDF108_ERROR";
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Kdf108Exception"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public Kdf108Exception(string message) : base(message)
    {
        ErrorCode = "KDF108_ERROR";
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Kdf108Exception"/> class with a specified error message and error code.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="errorCode">The error code associated with this exception.</param>
    public Kdf108Exception(string message, string errorCode) : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Kdf108Exception"/> class with a specified error message and inner exception.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public Kdf108Exception(string message, Exception innerException) : base(message, innerException)
    {
        ErrorCode = "KDF108_ERROR";
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Kdf108Exception"/> class with a specified error message, error code, and inner exception.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="errorCode">The error code associated with this exception.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public Kdf108Exception(string message, string errorCode, Exception innerException) : base(message, innerException)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Kdf108Exception"/> class with a specified error message, error code, context, and inner exception.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="errorCode">The error code associated with this exception.</param>
    /// <param name="context">Additional context information about the error.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public Kdf108Exception(string message, string errorCode, string context, Exception? innerException = null) 
        : base(message, innerException)
    {
        ErrorCode = errorCode;
        Context = context;
    }

}
