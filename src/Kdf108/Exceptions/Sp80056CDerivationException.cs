// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Exceptions;

/// <summary>
/// Exception thrown when SP 800-56C key derivation pipeline operations fail.
/// </summary>
public class Sp80056CDerivationException : Kdf108Exception
{
    /// <summary>
    /// Gets the pipeline stage where the failure occurred.
    /// </summary>
    public PipelineStage Stage { get; }

    /// <summary>
    /// Gets whether this was a two-step derivation.
    /// </summary>
    public bool IsTwoStep { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056CDerivationException"/> class.
    /// </summary>
    public Sp80056CDerivationException() 
        : base("Key derivation pipeline failed.", "SP80056C_DERIVATION_ERROR")
    {
        Stage = PipelineStage.Unknown;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056CDerivationException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public Sp80056CDerivationException(string message) 
        : base(message, "SP80056C_DERIVATION_ERROR")
    {
        Stage = PipelineStage.Unknown;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056CDerivationException"/> class with a specified error message and pipeline stage.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="stage">The pipeline stage where the failure occurred.</param>
    /// <param name="isTwoStep">Whether this was a two-step derivation.</param>
    public Sp80056CDerivationException(string message, PipelineStage stage, bool isTwoStep = false) 
        : base(message, $"SP80056C_{stage.ToString().ToUpperInvariant()}_ERROR", $"Stage: {stage}, TwoStep: {isTwoStep}")
    {
        Stage = stage;
        IsTwoStep = isTwoStep;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056CDerivationException"/> class with a specified error message and inner exception.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public Sp80056CDerivationException(string message, Exception innerException) 
        : base(message, "SP80056C_DERIVATION_ERROR", innerException)
    {
        Stage = PipelineStage.Unknown;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056CDerivationException"/> class with detailed context.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="stage">The pipeline stage where the failure occurred.</param>
    /// <param name="isTwoStep">Whether this was a two-step derivation.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public Sp80056CDerivationException(string message, PipelineStage stage, bool isTwoStep, Exception innerException)
        : base(message, $"SP80056C_{stage.ToString().ToUpperInvariant()}_ERROR", $"Stage: {stage}, TwoStep: {isTwoStep}", innerException)
    {
        Stage = stage;
        IsTwoStep = isTwoStep;
    }

}

/// <summary>
/// Specifies the pipeline stage where a failure occurred.
/// </summary>
public enum PipelineStage
{
    /// <summary>
    /// Unknown stage.
    /// </summary>
    Unknown,

    /// <summary>
    /// Key agreement stage.
    /// </summary>
    KeyAgreement,

    /// <summary>
    /// Extraction stage (two-step mode).
    /// </summary>
    Extraction,

    /// <summary>
    /// Expansion stage.
    /// </summary>
    Expansion,

    /// <summary>
    /// Validation stage.
    /// </summary>
    Validation,

    /// <summary>
    /// Shared secret processing.
    /// </summary>
    SharedSecretProcessing
}
