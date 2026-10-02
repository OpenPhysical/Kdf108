// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Exceptions;

/// <summary>
/// Exception thrown when a private key value is zero.
/// </summary>
public class PrivateKeyZeroException : InvalidPrivateKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyZeroException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PrivateKeyZeroException(string message) 
        : base(message, PrivateKeyValidationFailure.Zero)
    {
    }
}

/// <summary>
/// Exception thrown when a private key value is negative.
/// </summary>
public class PrivateKeyNegativeException : InvalidPrivateKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyNegativeException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PrivateKeyNegativeException(string message) 
        : base(message, PrivateKeyValidationFailure.Negative)
    {
    }
}

/// <summary>
/// Exception thrown when a private key value is too large (>= n).
/// </summary>
public class PrivateKeyTooLargeException : InvalidPrivateKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyTooLargeException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PrivateKeyTooLargeException(string message) 
        : base(message, PrivateKeyValidationFailure.TooLarge)
    {
    }
}

/// <summary>
/// Exception thrown when a private key value is invalid according to NIST SP 800-56A validation rules.
/// This is used for CAVP test compliance when a private key has been tampered with.
/// </summary>
public class PrivateKeyTamperedException : InvalidPrivateKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyTamperedException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PrivateKeyTamperedException(string message) 
        : base(message, PrivateKeyValidationFailure.Tampered)
    {
    }
}

/// <summary>
/// Exception thrown when a private key has invalid length.
/// </summary>
public class PrivateKeyInvalidLengthException : InvalidPrivateKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyInvalidLengthException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PrivateKeyInvalidLengthException(string message) 
        : base(message, PrivateKeyValidationFailure.InvalidLength)
    {
    }
}

/// <summary>
/// Exception thrown when a private key cannot be decoded.
/// </summary>
public class PrivateKeyDecodingException : InvalidPrivateKeyException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyDecodingException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public PrivateKeyDecodingException(string message, Exception innerException) 
        : base(message, PrivateKeyValidationFailure.DecodingFailed, innerException)
    {
    }
}