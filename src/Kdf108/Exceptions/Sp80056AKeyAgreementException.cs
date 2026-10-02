// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Exceptions;

/// <summary>
/// Exception thrown when SP 800-56A key agreement operations fail.
/// </summary>
public class Sp80056AKeyAgreementException : Kdf108Exception
{
    /// <summary>
    /// Gets the type of key agreement failure.
    /// </summary>
    public KeyAgreementFailureType FailureType { get; }

    /// <summary>
    /// Gets the curve name where the failure occurred, if applicable.
    /// </summary>
    public string? CurveName { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056AKeyAgreementException"/> class.
    /// </summary>
    public Sp80056AKeyAgreementException() 
        : base("Key agreement failed.", "SP80056A_KEY_AGREEMENT_ERROR")
    {
        FailureType = KeyAgreementFailureType.General;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056AKeyAgreementException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public Sp80056AKeyAgreementException(string message) 
        : base(message, "SP80056A_KEY_AGREEMENT_ERROR")
    {
        FailureType = KeyAgreementFailureType.General;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056AKeyAgreementException"/> class with a specified error message and failure type.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="failureType">The type of key agreement failure.</param>
    public Sp80056AKeyAgreementException(string message, KeyAgreementFailureType failureType) 
        : base(message, $"SP80056A_{failureType.ToString().ToUpperInvariant()}")
    {
        FailureType = failureType;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056AKeyAgreementException"/> class with a specified error message, failure type, and curve name.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="failureType">The type of key agreement failure.</param>
    /// <param name="curveName">The name of the curve where the failure occurred.</param>
    public Sp80056AKeyAgreementException(string message, KeyAgreementFailureType failureType, string curveName) 
        : base(message, $"SP80056A_{failureType.ToString().ToUpperInvariant()}", $"Curve: {curveName}")
    {
        FailureType = failureType;
        CurveName = curveName;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056AKeyAgreementException"/> class with a specified error message and inner exception.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public Sp80056AKeyAgreementException(string message, Exception innerException) 
        : base(message, "SP80056A_KEY_AGREEMENT_ERROR", innerException)
    {
        FailureType = KeyAgreementFailureType.General;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056AKeyAgreementException"/> class with detailed context.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="failureType">The type of key agreement failure.</param>
    /// <param name="curveName">The name of the curve where the failure occurred.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public Sp80056AKeyAgreementException(string message, KeyAgreementFailureType failureType, string curveName, Exception innerException)
        : base(message, $"SP80056A_{failureType.ToString().ToUpperInvariant()}", $"Curve: {curveName}", innerException)
    {
        FailureType = failureType;
        CurveName = curveName;
    }

}

/// <summary>
/// Specifies the type of key agreement failure.
/// </summary>
public enum KeyAgreementFailureType
{
    /// <summary>
    /// General key agreement failure.
    /// </summary>
    General,

    /// <summary>
    /// Invalid private key.
    /// </summary>
    InvalidPrivateKey,

    /// <summary>
    /// Invalid public key.
    /// </summary>
    InvalidPublicKey,

    /// <summary>
    /// Keys are on different curves.
    /// </summary>
    CurveMismatch,

    /// <summary>
    /// Unsupported curve.
    /// </summary>
    UnsupportedCurve,

    /// <summary>
    /// Point not on curve.
    /// </summary>
    PointNotOnCurve,

    /// <summary>
    /// Point at infinity.
    /// </summary>
    PointAtInfinity,

    /// <summary>
    /// Invalid point order.
    /// </summary>
    InvalidPointOrder,

    /// <summary>
    /// Weak key detected.
    /// </summary>
    WeakKey
}
