// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Exceptions;

/// <summary>
/// Exception thrown when a public key X coordinate fails validation according to NIST SP 800-56A.
/// </summary>
public class InvalidPublicKeyXCoordinateException : InvalidPublicKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidPublicKeyXCoordinateException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public InvalidPublicKeyXCoordinateException(string message) 
        : base(message, PublicKeyValidationFailure.XCoordinateOutOfRange)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidPublicKeyXCoordinateException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public InvalidPublicKeyXCoordinateException(string message, Exception innerException) 
        : base(message, PublicKeyValidationFailure.XCoordinateOutOfRange, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a public key Y coordinate fails validation according to NIST SP 800-56A.
/// </summary>
public class InvalidPublicKeyYCoordinateException : InvalidPublicKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidPublicKeyYCoordinateException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public InvalidPublicKeyYCoordinateException(string message) 
        : base(message, PublicKeyValidationFailure.YCoordinateOutOfRange)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidPublicKeyYCoordinateException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public InvalidPublicKeyYCoordinateException(string message, Exception innerException) 
        : base(message, PublicKeyValidationFailure.YCoordinateOutOfRange, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a public key point is not on the specified elliptic curve.
/// </summary>
public class PublicKeyNotOnCurveException : InvalidPublicKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeyNotOnCurveException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PublicKeyNotOnCurveException(string message) 
        : base(message, PublicKeyValidationFailure.PointNotOnCurve)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeyNotOnCurveException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public PublicKeyNotOnCurveException(string message, Exception innerException) 
        : base(message, PublicKeyValidationFailure.PointNotOnCurve, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a public key point has incorrect order.
/// </summary>
public class PublicKeyIncorrectOrderException : InvalidPublicKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeyIncorrectOrderException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PublicKeyIncorrectOrderException(string message) 
        : base(message, PublicKeyValidationFailure.IncorrectOrder)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeyIncorrectOrderException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public PublicKeyIncorrectOrderException(string message, Exception innerException) 
        : base(message, PublicKeyValidationFailure.IncorrectOrder, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a public key point is at infinity.
/// </summary>
public class PublicKeyAtInfinityException : InvalidPublicKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeyAtInfinityException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PublicKeyAtInfinityException(string message) 
        : base(message, PublicKeyValidationFailure.PointAtInfinity)
    {
    }
}

/// <summary>
/// Exception thrown when a public key is in a small subgroup.
/// </summary>
public class PublicKeySmallSubgroupException : InvalidPublicKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeySmallSubgroupException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PublicKeySmallSubgroupException(string message) 
        : base(message, PublicKeyValidationFailure.SmallSubgroup)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeySmallSubgroupException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public PublicKeySmallSubgroupException(string message, Exception innerException) 
        : base(message, PublicKeyValidationFailure.SmallSubgroup, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a public key has invalid format.
/// </summary>
public class PublicKeyInvalidFormatException : InvalidPublicKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeyInvalidFormatException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PublicKeyInvalidFormatException(string message) 
        : base(message, PublicKeyValidationFailure.InvalidFormat)
    {
    }
}

/// <summary>
/// Exception thrown when a public key has invalid length.
/// </summary>
public class PublicKeyInvalidLengthException : InvalidPublicKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeyInvalidLengthException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PublicKeyInvalidLengthException(string message) 
        : base(message, PublicKeyValidationFailure.InvalidLength)
    {
    }
}

/// <summary>
/// Exception thrown when a public key cannot be decoded.
/// </summary>
public class PublicKeyDecodingException : InvalidPublicKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeyDecodingException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public PublicKeyDecodingException(string message, Exception innerException) 
        : base(message, PublicKeyValidationFailure.DecodingFailed, innerException)
    {
    }
}