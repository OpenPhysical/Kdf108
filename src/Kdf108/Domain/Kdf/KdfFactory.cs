// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Interfaces.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Kdf108.Exceptions;
using Microsoft.Extensions.Logging;

namespace Kdf108.Domain.Kdf;

/// <summary>
/// Factory for creating KDF instances with proper dependency injection.
/// </summary>
public class KdfFactory : IKdfFactory
{
    private readonly ILoggerFactory? _loggerFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="KdfFactory"/> class.
    /// </summary>
    /// <param name="loggerFactory">Optional logger factory for creating loggers.</param>
    public KdfFactory(ILoggerFactory? loggerFactory = null)
    {
        _loggerFactory = loggerFactory;
    }

    /// <inheritdoc/>
    public IKdf CreateKdf(KdfMode mode, bool useCounter = false)
    {
        var (baseMode, shouldUseCounter) = DecomposeMode(mode, useCounter);

        return baseMode switch
        {
            KdfMode.Counter => new CounterModeKdf(_loggerFactory?.CreateLogger<CounterModeKdf>()),
            KdfMode.Feedback => new FeedbackModeKdf(shouldUseCounter, _loggerFactory?.CreateLogger<FeedbackModeKdf>()),
            KdfMode.DoublePipeline => new DoublePipelineKdf(shouldUseCounter),
            _ => throw new KdfDerivationException($"Unsupported KDF mode: {mode}", mode, PrfType.HmacSha256, 0)
        };
    }

    private static (KdfMode baseMode, bool useCounter) DecomposeMode(KdfMode mode, bool useCounterOverride)
    {
        return mode switch
        {
            KdfMode.Counter => (KdfMode.Counter, false),
            KdfMode.Feedback => (KdfMode.Feedback, useCounterOverride),
            KdfMode.FeedbackWithCounter => (KdfMode.Feedback, true),
            KdfMode.DoublePipeline => (KdfMode.DoublePipeline, useCounterOverride),
            KdfMode.DoublePipelineWithCounter => (KdfMode.DoublePipeline, true),
            _ => throw new ArgumentOutOfRangeException(nameof(mode), $"Unsupported KDF mode: {mode}")
        };
    }
}
