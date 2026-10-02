// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using FluentValidation;
using FluentValidation.Results;
using Kdf108.Domain.Kdf;

namespace Kdf108.Domain.Validator;

internal static class KdfInputValidator
{
    private static readonly KdfRequestValidator s_validator = new();

    public static void ValidateFixedInput(
        byte[] kdk, byte[] fixedInput, long outputLengthInBits, KdfOptions options)
    {
        KdfRequest request = new(kdk, string.Empty, fixedInput, outputLengthInBits, options);
        ValidationResult result = s_validator.Validate(request);
        if (!result.IsValid)
        {
            throw new ValidationException(result.Errors);
        }
    }
}
