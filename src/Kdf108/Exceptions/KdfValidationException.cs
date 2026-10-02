// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using FluentValidation.Results;

namespace Kdf108.Exceptions;

/// <summary>
/// Exception thrown when validation fails for KDF operations.
/// </summary>
public class KdfValidationException : Kdf108Exception
{
    /// <summary>
    /// Gets the validation errors that caused this exception.
    /// </summary>
    public IReadOnlyList<ValidationError> ValidationErrors { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KdfValidationException"/> class.
    /// </summary>
    public KdfValidationException() 
        : base("Validation failed.", "KDF_VALIDATION_ERROR")
    {
        ValidationErrors = Array.Empty<ValidationError>();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KdfValidationException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public KdfValidationException(string message) 
        : base(message, "KDF_VALIDATION_ERROR")
    {
        ValidationErrors = Array.Empty<ValidationError>();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KdfValidationException"/> class from FluentValidation failures.
    /// </summary>
    /// <param name="failures">The validation failures.</param>
    public KdfValidationException(IEnumerable<ValidationFailure> failures) 
        : base(CreateMessage(failures), "KDF_VALIDATION_ERROR")
    {
        ValidationErrors = failures.Select(f => new ValidationError
        {
            PropertyName = f.PropertyName,
            ErrorMessage = f.ErrorMessage,
            ErrorCode = f.ErrorCode,
            AttemptedValue = f.AttemptedValue?.ToString()
        }).ToList();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KdfValidationException"/> class with validation errors.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="errors">The validation errors.</param>
    public KdfValidationException(string message, IEnumerable<ValidationError> errors) 
        : base(message, "KDF_VALIDATION_ERROR", FormatErrors(errors))
    {
        ValidationErrors = errors.ToList();
    }


    private static string CreateMessage(IEnumerable<ValidationFailure> failures)
    {
        var errors = failures.Select(f => $"{f.PropertyName}: {f.ErrorMessage}");
        return $"Validation failed: {string.Join("; ", errors)}";
    }

    private static string FormatErrors(IEnumerable<ValidationError> errors)
    {
        return string.Join("; ", errors.Select(e => $"{e.PropertyName}: {e.ErrorMessage}"));
    }
}

/// <summary>
/// Represents a validation error.
/// </summary>
public class ValidationError
{
    /// <summary>
    /// Gets or sets the name of the property that failed validation.
    /// </summary>
    public string PropertyName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the error message.
    /// </summary>
    public string ErrorMessage { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the error code.
    /// </summary>
    public string? ErrorCode { get; set; }

    /// <summary>
    /// Gets or sets the attempted value that failed validation.
    /// </summary>
    public string? AttemptedValue { get; set; }
}
