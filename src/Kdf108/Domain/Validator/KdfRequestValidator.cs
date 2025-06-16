// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using FluentValidation;
using Kdf108.Domain.Kdf;

#endregion

namespace Kdf108.Domain.Validator
{
    public sealed class KdfRequestValidator : AbstractValidator<KdfRequest>
    {
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
                .InclusiveBetween(8, 32)
                .WithMessage("Counter length must be between 8 and 32 bits (inclusive).");

            RuleFor(static x => x.Options.PrfType)
                .IsInEnum()
                .WithMessage("PRF type must be a valid enumeration value.");
        }
    }
}
