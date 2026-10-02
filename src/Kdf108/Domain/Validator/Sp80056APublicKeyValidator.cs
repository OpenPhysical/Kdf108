// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using FluentValidation;
using Kdf108.Domain.Sp80056A;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kdf108.Domain.Validator;

/// <summary>
/// Validator for SP 800-56A EC public keys.
/// Ensures the public key meets all requirements specified in NIST SP 800-56A.
/// </summary>
public class Sp80056APublicKeyValidator : AbstractValidator<Sp80056APublicKey>
{
    private readonly ILogger<Sp80056APublicKeyValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056APublicKeyValidator"/> class.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public Sp80056APublicKeyValidator(ILogger<Sp80056APublicKeyValidator>? logger = null)
    {
        _logger = logger ?? NullLogger<Sp80056APublicKeyValidator>.Instance;

        RuleFor(x => x)
            .NotNull()
            .WithMessage("Public key cannot be null");

        RuleFor(x => x.PublicPoint)
            .NotNull()
            .WithMessage("Public key point cannot be null")
            .Must(NotBeAtInfinity)
            .WithMessage("Public key point cannot be at infinity")
            .Must(BeOnCurve)
            .WithMessage("Public key point must be on the curve");

        RuleFor(x => x.DomainParameters)
            .NotNull()
            .WithMessage("Domain parameters cannot be null");

        RuleFor(x => x.CurveName)
            .NotEmpty()
            .WithMessage("Curve name must be specified")
            .Must(BeApprovedCurve)
            .WithMessage("Curve '{PropertyValue}' is not an approved curve for SP 800-56A");

        RuleFor(x => x)
            .Must(HaveCorrectOrder)
            .WithMessage("Public key point does not have the correct order")
            .When(x => x.PublicPoint != null && x.DomainParameters != null);

        // Log validation attempts
        RuleFor(x => x.CurveName)
            .Must((key, curveName) =>
            {
                _logger.LogDebug("Validating public key on curve: {CurveName}", curveName);
                return true;
            })
            .WithMessage("Validation logging");
    }

    /// <summary>
    /// Checks if the public key point is not at infinity.
    /// </summary>
    private bool NotBeAtInfinity(Org.BouncyCastle.Math.EC.ECPoint point)
    {
        if (point == null) return false;
        
        var isValid = !point.IsInfinity;
        if (!isValid)
        {
            _logger.LogWarning("Public key validation failed: point at infinity");
        }
        return isValid;
    }

    /// <summary>
    /// Checks if the public key point is on the curve.
    /// </summary>
    private bool BeOnCurve(Org.BouncyCastle.Math.EC.ECPoint point)
    {
        if (point == null) return false;
        
        try
        {
            var isValid = point.IsValid();
            if (!isValid)
            {
                _logger.LogWarning("Public key validation failed: point not on curve");
            }
            return isValid;
        }
        catch
        {
            _logger.LogError("Error checking if point is on curve");
            return false;
        }
    }

    /// <summary>
    /// Checks if the curve is approved for use with SP 800-56A.
    /// </summary>
    private bool BeApprovedCurve(string curveName)
    {
        if (string.IsNullOrEmpty(curveName)) return false;

        // NIST approved curves for ECDH (including both prime and binary curves)
        var approvedCurves = new[]
        {
            // Prime curves
            "P-224", "P-256", "P-384", "P-521",
            "secp224r1", "secp256r1", "secp384r1", "secp521r1",
            "prime256v1", "prime384v1", "prime521v1",
            // Binary curves
            "B-233", "K-233", "K-283", "B-409", "B-571", "K-571",
            "sect233r1", "sect233k1", "sect283k1", "sect409r1", "sect571r1", "sect571k1"
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
    /// Checks if the public key point has the correct order.
    /// </summary>
    private bool HaveCorrectOrder(Sp80056APublicKey publicKey)
    {
        try
        {
            var nQ = publicKey.PublicPoint.Multiply(publicKey.DomainParameters.N);
            var isValid = nQ.IsInfinity;
            
            if (!isValid)
            {
                _logger.LogWarning("Public key validation failed: point order incorrect");
            }
            
            return isValid;
        }
        catch
        {
            _logger.LogError("Error checking public key point order");
            return false;
        }
    }
}
