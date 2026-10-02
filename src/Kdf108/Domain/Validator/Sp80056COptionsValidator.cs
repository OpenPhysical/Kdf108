// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using FluentValidation;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Sp80056C;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kdf108.Domain.Validator;

/// <summary>
/// Validator for SP 800-56C pipeline options.
/// Ensures the options meet all requirements for secure key derivation.
/// </summary>
internal class Sp80056COptionsValidator : AbstractValidator<Sp80056COptions>
{
    private readonly ILogger<Sp80056COptionsValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056COptionsValidator"/> class.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public Sp80056COptionsValidator(ILogger<Sp80056COptionsValidator>? logger = null)
    {
        _logger = logger ?? NullLogger<Sp80056COptionsValidator>.Instance;

        RuleFor(x => x.Label)
            .NotEmpty()
            .WithMessage("Label must be specified for key derivation")
            .MaximumLength(256)
            .WithMessage("Label must not exceed 256 characters");

        RuleFor(x => x.OutputLengthInBits)
            .GreaterThan(0)
            .WithMessage("Output length must be positive")
            .LessThanOrEqualTo(1024 * 8) // 1024 bytes max
            .WithMessage("Output length must not exceed 8192 bits (1024 bytes)")
            .Must(BeMultipleOf8)
            .WithMessage("Output length must be a multiple of 8 bits");

        RuleFor(x => x.Context)
            .NotNull()
            .WithMessage("Context cannot be null (use empty array if no context needed)");

        RuleFor(x => x.CounterLengthBits)
            .Must(BeValidCounterLength)
            .WithMessage("Counter length must be between 1 and 32 bits");

        RuleFor(x => x.KdfMode)
            .IsInEnum()
            .WithMessage("Invalid KDF mode specified");

        RuleFor(x => x.CounterLocation)
            .IsInEnum()
            .WithMessage("Invalid counter location specified");

        RuleFor(x => x.ExtractionPrfType)
            .IsInEnum()
            .WithMessage("Invalid extraction PRF type specified")
            .When(x => x.UseTwoStep);

        RuleFor(x => x.ExpansionPrfType)
            .IsInEnum()
            .WithMessage("Invalid expansion PRF type specified");

        // Salt validation for two-step mode
        RuleFor(x => x.Salt)
            .Must((options, salt) => salt == null || ValidateSaltForTwoStep(salt, options.ExtractionPrfType))
            .WithMessage("Salt size should match the extraction PRF output size for optimal security")
            .When(x => x.UseTwoStep && x.Salt != null && x.Salt.Length > 0);

        // OtherInfo validation
        RuleFor(x => x.OtherInfo)
            .Must(BeReasonableSize)
            .WithMessage("OtherInfo size must not exceed 65536 bytes")
            .When(x => x.OtherInfo != null);

        // Security warnings
        RuleFor(x => x)
            .Must(options =>
            {
                if (options.OutputLengthInBits > 512 && options.ExpansionPrfType == PrfType.HmacSha1)
                {
                    _logger.LogWarning("Using SHA-1 for large output lengths is not recommended");
                    return true; // Still valid, just a warning
                }
                return true;
            })
            .WithMessage("Security configuration check");

        // Log validation
        RuleFor(x => x)
            .Must(options =>
            {
                _logger.LogDebug("Validating SP 800-56C options: TwoStep={UseTwoStep}, KdfMode={KdfMode}, OutputBits={OutputBits}",
                    options.UseTwoStep, options.KdfMode, options.OutputLengthInBits);
                return true;
            })
            .WithMessage("Validation logging");
    }

    /// <summary>
    /// Checks if the output length is a multiple of 8 bits.
    /// </summary>
    private bool BeMultipleOf8(long outputLengthInBits)
    {
        return outputLengthInBits % 8 == 0;
    }

    /// <summary>
    /// Checks if the counter length is valid per SP 800-108.
    /// </summary>
    private static bool BeValidCounterLength(int counterLengthBits) =>
        counterLengthBits is >= 1 and <= 32;

    /// <summary>
    /// Validates salt size for two-step mode.
    /// </summary>
    private bool ValidateSaltForTwoStep(byte[] salt, PrfType extractionPrfType)
    {
        if (salt == null) return true;

        // Get expected salt size based on PRF
        int expectedSize = extractionPrfType switch
        {
            PrfType.HmacSha1 => 20,
            PrfType.HmacSha224 => 28,
            PrfType.HmacSha256 => 32,
            PrfType.HmacSha384 => 48,
            PrfType.HmacSha512 => 64,
            PrfType.CmacAes128 => 16,
            PrfType.CmacAes192 => 16,
            PrfType.CmacAes256 => 16,
            PrfType.CmacTdes3 => 8,
            _ => 32
        };

        if (salt.Length != expectedSize)
        {
            _logger.LogWarning("Salt size {ActualSize} does not match recommended size {ExpectedSize} for {PrfType}",
                salt.Length, expectedSize, extractionPrfType);
        }

        return true; // Not a hard requirement, just a recommendation
    }

    /// <summary>
    /// Checks if OtherInfo is a reasonable size.
    /// </summary>
    private bool BeReasonableSize(byte[]? otherInfo)
    {
        if (otherInfo == null) return true;
        
        const int maxSize = 65536; // 64KB
        if (otherInfo.Length > maxSize)
        {
            _logger.LogWarning("OtherInfo size {Size} exceeds recommended maximum of {MaxSize} bytes",
                otherInfo.Length, maxSize);
            return false;
        }

        return true;
    }
}
