// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using FluentValidation;
using Kdf108.Domain.Sp80056A;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Math;

namespace Kdf108.Domain.Validator;

/// <summary>
/// Validator for SP 800-56A EC private keys.
/// Ensures the private key meets all requirements specified in NIST SP 800-56A.
/// </summary>
public class Sp80056APrivateKeyValidator : AbstractValidator<Sp80056APrivateKey>
{
    private readonly ILogger<Sp80056APrivateKeyValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056APrivateKeyValidator"/> class.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public Sp80056APrivateKeyValidator(ILogger<Sp80056APrivateKeyValidator>? logger = null)
    {
        _logger = logger ?? NullLogger<Sp80056APrivateKeyValidator>.Instance;

        RuleFor(x => x)
            .NotNull()
            .WithMessage("Private key cannot be null");

        RuleFor(x => x.D)
            .NotNull()
            .WithMessage("Private key value (d) cannot be null")
            .Must((key, d) => BeInValidRange(d, key.DomainParameters))
            .WithMessage("Private key value must be in range [1, n-1]")
            .When(x => x.DomainParameters != null);

        RuleFor(x => x.DomainParameters)
            .NotNull()
            .WithMessage("Domain parameters cannot be null");

        RuleFor(x => x.CurveName)
            .NotEmpty()
            .WithMessage("Curve name must be specified")
            .Must(BeApprovedCurve)
            .WithMessage("Curve '{PropertyValue}' is not an approved curve for SP 800-56A");

        // Additional security checks
        RuleFor(x => x.D)
            .Must(NotBeWeakKey)
            .WithMessage("Private key appears to be weak or predictable")
            .When(x => x.D != null);

        // Log validation attempts
        RuleFor(x => x.CurveName)
            .Must((key, curveName) =>
            {
                _logger.LogDebug("Validating private key on curve: {CurveName}", curveName);
                return true;
            })
            .WithMessage("Validation logging");
    }

    /// <summary>
    /// Checks if the private key value is in the valid range [1, n-1].
    /// </summary>
    private bool BeInValidRange(BigInteger d, Org.BouncyCastle.Crypto.Parameters.ECDomainParameters domainParams)
    {
        if (d == null || domainParams == null) return false;

        var n = domainParams.N;
        var isValid = d.CompareTo(BigInteger.One) >= 0 && d.CompareTo(n.Subtract(BigInteger.One)) <= 0;

        if (!isValid)
        {
            _logger.LogWarning("Private key validation failed: value not in range [1, n-1]");
        }

        return isValid;
    }

    /// <summary>
    /// Checks if the curve is approved for use with SP 800-56A.
    /// </summary>
    private bool BeApprovedCurve(string curveName)
    {
        if (string.IsNullOrEmpty(curveName)) return false;

        // NIST approved curves for ECDH
        var approvedCurves = new[]
        {
            "P-256", "P-384", "P-521",
            "secp256r1", "secp384r1", "secp521r1",
            "prime256v1", "prime384v1", "prime521v1"
        };

        foreach (var approved in approvedCurves)
        {
            if (curveName.Equals(approved, System.StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        _logger.LogWarning("Curve {CurveName} is not an approved curve for SP 800-56A", curveName);
        return false;
    }

    /// <summary>
    /// Performs basic checks to ensure the private key is not obviously weak.
    /// </summary>
    private bool NotBeWeakKey(BigInteger d)
    {
        if (d == null) return false;

        // Check for small values (less than 2^32)
        var smallThreshold = BigInteger.One.ShiftLeft(32);
        if (d.CompareTo(smallThreshold) < 0)
        {
            _logger.LogWarning("Private key validation warning: key value is suspiciously small");
            return false;
        }

        // Check for values that are all zeros except for a few bits
        var bitCount = d.BitCount;
        var bitLength = d.BitLength;
        if (bitLength > 32 && bitCount < 5)
        {
            _logger.LogWarning("Private key validation warning: key has very low hamming weight");
            return false;
        }

        return true;
    }
}
