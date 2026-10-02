// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Exceptions;

/// <summary>
/// Exception thrown when a public key is invalid for cryptographic operations.
/// </summary>
public class InvalidPublicKeyException : Sp80056AKeyAgreementException
{
    /// <summary>
    /// Gets the type of validation failure.
    /// </summary>
    public new PublicKeyValidationFailure FailureType { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidPublicKeyException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="failureType">The type of validation failure.</param>
    public InvalidPublicKeyException(string message, PublicKeyValidationFailure failureType) 
        : base(message)
    {
        FailureType = failureType;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidPublicKeyException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="failureType">The type of validation failure.</param>
    /// <param name="innerException">The inner exception.</param>
    public InvalidPublicKeyException(string message, PublicKeyValidationFailure failureType, Exception innerException) 
        : base(message, innerException)
    {
        FailureType = failureType;
    }
}

/// <summary>
/// Types of public key validation failures.
/// </summary>
public enum PublicKeyValidationFailure
{
    /// <summary>
    /// The public key has an invalid length.
    /// </summary>
    InvalidLength,

    /// <summary>
    /// The public key has an invalid format (not uncompressed).
    /// </summary>
    InvalidFormat,

    /// <summary>
    /// The public key point is at infinity.
    /// </summary>
    PointAtInfinity,

    /// <summary>
    /// The public key point is not on the curve.
    /// </summary>
    PointNotOnCurve,

    /// <summary>
    /// The public key point has incorrect order.
    /// </summary>
    IncorrectOrder,

    /// <summary>
    /// The public key X coordinate is out of range.
    /// </summary>
    XCoordinateOutOfRange,

    /// <summary>
    /// The public key Y coordinate is out of range.
    /// </summary>
    YCoordinateOutOfRange,

    /// <summary>
    /// The public key point is in a small subgroup.
    /// </summary>
    SmallSubgroup,

    /// <summary>
    /// The public key could not be decoded.
    /// </summary>
    DecodingFailed
}