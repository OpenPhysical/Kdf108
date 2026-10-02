// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Exceptions;

/// <summary>
/// Base exception for all cryptographic operations.
/// </summary>
public abstract class CryptographicException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CryptographicException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    protected CryptographicException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="CryptographicException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    protected CryptographicException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Base exception for key-related errors.
/// </summary>
public abstract class InvalidKeyException : CryptographicException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidKeyException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    protected InvalidKeyException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidKeyException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    protected InvalidKeyException(string message, Exception innerException) : base(message, innerException) { }
}


/// <summary>
/// Exception thrown when keys do not form a valid pair.
/// </summary>
public sealed class KeyMismatchException : InvalidKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="KeyMismatchException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public KeyMismatchException(string message) : base(message) { }

    /// <summary>
    /// Creates an exception for mismatched curves.
    /// </summary>
    /// <param name="expectedCurve">The expected curve name.</param>
    /// <param name="actualCurve">The actual curve name.</param>
    /// <returns>A new exception instance.</returns>
    public static KeyMismatchException Create(string expectedCurve, string actualCurve) =>
        new($"Key curve mismatch: expected {expectedCurve}, got {actualCurve}");

    /// <summary>
    /// Creates an exception for keys that don't form a valid pair.
    /// </summary>
    /// <returns>A new exception instance.</returns>
    public static KeyMismatchException CreateForKeyPair() =>
        new("Public key does not correspond to private key - keys do not form a valid pair");
}

/// <summary>
/// Exception thrown when a curve is not supported.
/// </summary>
public sealed class UnsupportedCurveException : CryptographicException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UnsupportedCurveException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public UnsupportedCurveException(string message) : base(message) { }
}

/// <summary>
/// Exception thrown when key agreement fails.
/// </summary>
public sealed class KeyAgreementException : CryptographicException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="KeyAgreementException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public KeyAgreementException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyAgreementException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public KeyAgreementException(string message, Exception innerException) : base(message, innerException) { }
}

