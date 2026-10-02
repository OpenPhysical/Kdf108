// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Exceptions;

/// <summary>
/// Exception thrown when a private key is invalid for cryptographic operations.
/// </summary>
public class InvalidPrivateKeyException : Sp80056AKeyAgreementException
{
    /// <summary>
    /// Gets the type of validation failure.
    /// </summary>
    public new PrivateKeyValidationFailure FailureType { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidPrivateKeyException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="failureType">The type of validation failure.</param>
    public InvalidPrivateKeyException(string message, PrivateKeyValidationFailure failureType) 
        : base(message)
    {
        FailureType = failureType;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidPrivateKeyException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="failureType">The type of validation failure.</param>
    /// <param name="innerException">The inner exception.</param>
    public InvalidPrivateKeyException(string message, PrivateKeyValidationFailure failureType, Exception innerException) 
        : base(message, innerException)
    {
        FailureType = failureType;
    }
}

/// <summary>
/// Types of private key validation failures.
/// </summary>
public enum PrivateKeyValidationFailure
{
    /// <summary>
    /// The private key is zero.
    /// </summary>
    Zero,

    /// <summary>
    /// The private key is negative.
    /// </summary>
    Negative,

    /// <summary>
    /// The private key is greater than or equal to the curve order.
    /// </summary>
    TooLarge,

    /// <summary>
    /// The private key has an invalid format.
    /// </summary>
    InvalidFormat,

    /// <summary>
    /// The private key has been tampered with (for CAVP test compliance).
    /// </summary>
    Tampered,

    /// <summary>
    /// The private key has an invalid length.
    /// </summary>
    InvalidLength,

    /// <summary>
    /// The private key could not be decoded.
    /// </summary>
    DecodingFailed
}