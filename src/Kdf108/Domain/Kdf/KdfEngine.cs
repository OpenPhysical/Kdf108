// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using Kdf108.Domain.Interfaces.Kdf;
using Kdf108.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kdf108.Domain.Kdf;

/// <summary>
/// The KDF engine provides methods to derive keys using various Key Derivation Function (KDF) modes.
/// This is the main entry point for key derivation operations in the library.
/// </summary>
public class KdfEngine : IKdfEngine
{
    private readonly IKdfFactory _kdfFactory;
    private readonly ILogger<KdfEngine> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="KdfEngine"/> class.
    /// </summary>
    /// <param name="kdfFactory">The factory for creating KDF instances.</param>
    /// <param name="logger">Optional logger for operation logging.</param>
    public KdfEngine(IKdfFactory kdfFactory, ILogger<KdfEngine>? logger = null)
    {
        _kdfFactory = kdfFactory ?? throw new ArgumentNullException(nameof(kdfFactory));
        _logger = logger ?? NullLogger<KdfEngine>.Instance;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KdfEngine"/> class with a logger factory.
    /// </summary>
    /// <param name="loggerFactory">Optional logger factory for creating loggers.</param>
    public KdfEngine(ILoggerFactory? loggerFactory = null)
    {
        _kdfFactory = new KdfFactory(loggerFactory);
        _logger = loggerFactory?.CreateLogger<KdfEngine>() ?? NullLogger<KdfEngine>.Instance;
    }

    /// <inheritdoc/>
    public byte[] Derive(
        KdfMode mode,
        byte[] kdk,
        string label,
        byte[] context,
        long outputLengthInBits,
        KdfOptions options)
    {
        if (kdk == null) throw new ArgumentNullException(nameof(kdk));
        if (label == null) throw new ArgumentNullException(nameof(label));
        if (context == null) throw new ArgumentNullException(nameof(context));
        if (options == null) throw new ArgumentNullException(nameof(options));
        if (outputLengthInBits <= 0) throw new ArgumentOutOfRangeException(nameof(outputLengthInBits), "Output length must be positive");

        _logger.LogDebug("Starting key derivation. Mode: {Mode}, Label: {Label}, OutputBits: {OutputBits}, PRF: {PrfType}",
            mode, label, outputLengthInBits, options.PrfType);

        try
        {
            // Determine if we need to use counter based on the mode
            var useCounter = mode == KdfMode.FeedbackWithCounter || mode == KdfMode.DoublePipelineWithCounter;
            
            // Create the appropriate KDF instance
            var kdf = _kdfFactory.CreateKdf(mode, useCounter);

            // Perform the derivation
            var result = kdf.DeriveKey(kdk, label, context, outputLengthInBits, options);

            _logger.LogInformation("Key derivation completed successfully. Mode: {Mode}, OutputBits: {OutputBits}",
                mode, outputLengthInBits);

            return result;
        }
        catch (KdfDerivationException)
        {
            // Already properly typed, just rethrow
            throw;
        }
        catch (KdfValidationException)
        {
            // Already properly typed, just rethrow
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during key derivation");
            throw new KdfDerivationException(
                "An unexpected error occurred during key derivation",
                mode,
                options.PrfType,
                outputLengthInBits,
                ex);
        }
    }

    /// <inheritdoc/>
    public async Task<byte[]> DeriveAsync(
        KdfMode mode,
        byte[] kdk,
        string label,
        byte[] context,
        long outputLengthInBits,
        KdfOptions options,
        CancellationToken cancellationToken = default)
    {
        // For CPU-bound operations like KDF, we use Task.Run to avoid blocking
        return await Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Derive(mode, kdk, label, context, outputLengthInBits, options);
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a default KDF engine instance with no logging.
    /// </summary>
    /// <returns>A new KDF engine instance.</returns>
    public static IKdfEngine CreateDefault()
    {
        return new KdfEngine();
    }

    /// <summary>
    /// Creates a KDF engine instance with the specified logger factory.
    /// </summary>
    /// <param name="loggerFactory">The logger factory to use.</param>
    /// <returns>A new KDF engine instance.</returns>
    public static IKdfEngine Create(ILoggerFactory loggerFactory)
    {
        return new KdfEngine(loggerFactory);
    }
}
