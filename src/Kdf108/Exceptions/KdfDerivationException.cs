// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Kdf;

namespace Kdf108.Exceptions;

/// <summary>
/// Exception thrown when key derivation operations fail.
/// </summary>
public class KdfDerivationException : Kdf108Exception
{
    /// <summary>
    /// Gets the KDF mode that was being used when the exception occurred.
    /// </summary>
    public KdfMode? Mode { get; }

    /// <summary>
    /// Gets the PRF type that was being used when the exception occurred.
    /// </summary>
    public PrfType? PrfType { get; }

    /// <summary>
    /// Gets the requested output length in bits.
    /// </summary>
    public long? OutputLengthInBits { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KdfDerivationException"/> class.
    /// </summary>
    public KdfDerivationException() : base("Key derivation failed.", "KDF_DERIVATION_ERROR")
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KdfDerivationException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public KdfDerivationException(string message) : base(message, "KDF_DERIVATION_ERROR")
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KdfDerivationException"/> class with a specified error message and inner exception.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public KdfDerivationException(string message, Exception innerException) 
        : base(message, "KDF_DERIVATION_ERROR", innerException)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KdfDerivationException"/> class with detailed context.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="mode">The KDF mode being used.</param>
    /// <param name="prfType">The PRF type being used.</param>
    /// <param name="outputLengthInBits">The requested output length.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public KdfDerivationException(string message, KdfMode mode, PrfType prfType, long outputLengthInBits, Exception? innerException = null)
        : base(message, "KDF_DERIVATION_ERROR", $"Mode: {mode}, PRF: {prfType}, OutputBits: {outputLengthInBits}", innerException)
    {
        Mode = mode;
        PrfType = prfType;
        OutputLengthInBits = outputLengthInBits;
    }

}
