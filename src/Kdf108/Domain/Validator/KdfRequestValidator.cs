// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using FluentValidation;
using Kdf108.Domain.Kdf;

namespace Kdf108.Domain.Validator;

/// <summary>
/// Validates <see cref="KdfRequest"/> instances to ensure all required properties are set
/// and meet the necessary constraints for key derivation operations.
/// </summary>
/// <remarks>
/// This validator enforces business rules such as non-null properties, valid ranges,
/// and consistency between related properties like output length and maximum allowed bits.
/// </remarks>
public sealed class KdfRequestValidator : AbstractValidator<KdfRequest>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="KdfRequestValidator"/> class with
    /// predefined validation rules for KDF requests.
    /// </summary>
    public KdfRequestValidator()
    {
        RuleFor(static x => x.KeyDerivationKey)
            .NotNull()
            .NotEmpty()
            .WithMessage("Base key must be provided and non-empty.");

        RuleFor(static x => x.Label)
            .NotNull()
            .WithMessage("Label must be provided.");

        RuleFor(static x => x.Context)
            .NotNull()
            .WithMessage("Context must not be null.");

        RuleFor(static x => x.OutputLengthBits)
            .GreaterThan(0)
            .WithMessage("Output length must be greater than 0 bits.")
            .Must(static (request, length) => length <= request.Options.MaxBitsAllowed)
            .WithMessage(static req =>
                $"Requested output length ({req.OutputLengthBits} bits) exceeds configured maximum ({req.Options.MaxBitsAllowed} bits).");

        RuleFor(static x => x.Options)
            .NotNull()
            .WithMessage("Options must be provided.");

        RuleFor(static x => x.Options.CounterLengthBits)
            .InclusiveBetween(1, 32)
            .WithMessage("Counter length must be between 1 and 32 bits (inclusive).");

        RuleFor(static x => x.Options.PrfType)
            .IsInEnum()
            .WithMessage("PRF type must be a valid enumeration value.");
    }
}
