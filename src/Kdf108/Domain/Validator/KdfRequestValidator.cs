// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using FluentValidation;
using Kdf108.Domain.Kdf;

#endregion

namespace Kdf108.Domain.Validator;

public sealed class KdfRequestValidator : AbstractValidator<KdfRequest>
{
    public KdfRequestValidator()
    {
        RuleFor(x => x.KeyDerivationKey)
            .NotNull()
            .NotEmpty()
            .WithMessage("Base key must be provided and non-empty.");

        RuleFor(x => x.Label)
            .NotNull()
            .WithMessage("Label must be provided.");

        RuleFor(x => x.Context)
            .NotNull()
            .WithMessage("Context must not be null.");

        RuleFor(x => x.OutputLengthBits)
            .GreaterThan(0)
            .WithMessage("Output length must be greater than 0 bits.")
            .Must((request, length) => length <= request.Options.MaxBitsAllowed)
            .WithMessage(req =>
                $"Requested output length ({req.OutputLengthBits} bits) exceeds configured maximum ({req.Options.MaxBitsAllowed} bits).");

        RuleFor(x => x.Options)
            .NotNull()
            .WithMessage("Options must be provided.");

        RuleFor(x => x.Options.CounterLengthBits)
            .InclusiveBetween(8, 32)
            .WithMessage("Counter length must be between 8 and 32 bits (inclusive).");

        RuleFor(x => x.Options.PrfType)
            .IsInEnum()
            .WithMessage("PRF type must be a valid enumeration value.");
    }
}
