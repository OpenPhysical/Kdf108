// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Kdf;

namespace Kdf108.Domain.Sp80056C;

/// <summary>
/// Configuration options for SP 800-56C key derivation pipelines.
/// </summary>
public class Sp80056COptions
{
    /// <summary>
    /// Gets or sets the label for the key derivation.
    /// </summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the context information for the key derivation.
    /// </summary>
    public byte[] Context { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Gets or sets the desired output length in bits.
    /// </summary>
    public long OutputLengthInBits { get; set; }

    /// <summary>
    /// Gets or sets the salt for the extraction step (optional).
    /// </summary>
    public byte[]? Salt { get; set; }

    /// <summary>
    /// Gets or sets the OtherInfo as specified in SP 800-56A (optional).
    /// </summary>
    public byte[]? OtherInfo { get; set; }

    /// <summary>
    /// Gets or sets whether to use two-step KDF (extract-then-expand).
    /// </summary>
    public bool UseTwoStep { get; set; } = false;

    /// <summary>
    /// Gets or sets the PRF type for the extraction step (if using two-step).
    /// </summary>
    public PrfType ExtractionPrfType { get; set; } = PrfType.HmacSha256;

    /// <summary>
    /// Gets or sets the PRF type for the expansion/KDF step.
    /// </summary>
    public PrfType ExpansionPrfType { get; set; } = PrfType.HmacSha256;

    /// <summary>
    /// Gets or sets the KDF mode for the expansion step.
    /// </summary>
    public KdfMode KdfMode { get; set; } = KdfMode.Counter;

    /// <summary>
    /// Gets or sets the counter length in bits for the KDF.
    /// </summary>
    public int CounterLengthBits { get; set; } = 32;

    /// <summary>
    /// Gets or sets the counter location for the KDF.
    /// </summary>
    public CounterLocation CounterLocation { get; set; } = CounterLocation.BeforeFixed;

    /// <summary>
    /// Creates a new builder for constructing Sp80056COptions.
    /// </summary>
    /// <returns>A new instance of Sp80056COptionsBuilder.</returns>
    public static Sp80056COptionsBuilder CreateBuilder() => new();
}

/// <summary>
/// Builder for constructing Sp80056COptions with a fluent interface.
/// </summary>
public class Sp80056COptionsBuilder
{
    private readonly Sp80056COptions _options = new();

    /// <summary>
    /// Sets the label for the key derivation.
    /// </summary>
    /// <param name="label">The label string.</param>
    /// <returns>The builder instance for chaining.</returns>
    public Sp80056COptionsBuilder WithLabel(string label)
    {
        _options.Label = label ?? throw new ArgumentNullException(nameof(label));
        return this;
    }

    /// <summary>
    /// Sets the context information for the key derivation.
    /// </summary>
    /// <param name="context">The context data.</param>
    /// <returns>The builder instance for chaining.</returns>
    public Sp80056COptionsBuilder WithContext(byte[] context)
    {
        _options.Context = context ?? throw new ArgumentNullException(nameof(context));
        return this;
    }

    /// <summary>
    /// Sets the desired output length in bits.
    /// </summary>
    /// <param name="outputLengthInBits">The output length in bits.</param>
    /// <returns>The builder instance for chaining.</returns>
    public Sp80056COptionsBuilder WithOutputLengthInBits(long outputLengthInBits)
    {
        if (outputLengthInBits <= 0)
            throw new ArgumentException("Output length must be positive", nameof(outputLengthInBits));
        
        _options.OutputLengthInBits = outputLengthInBits;
        return this;
    }

    /// <summary>
    /// Sets the desired output length in bytes.
    /// </summary>
    /// <param name="outputLengthInBytes">The output length in bytes.</param>
    /// <returns>The builder instance for chaining.</returns>
    public Sp80056COptionsBuilder WithOutputLengthInBytes(int outputLengthInBytes)
    {
        if (outputLengthInBytes <= 0)
            throw new ArgumentException("Output length must be positive", nameof(outputLengthInBytes));
        
        _options.OutputLengthInBits = outputLengthInBytes * 8L;
        return this;
    }

    /// <summary>
    /// Sets the salt for the extraction step.
    /// </summary>
    /// <param name="salt">The salt value.</param>
    /// <returns>The builder instance for chaining.</returns>
    public Sp80056COptionsBuilder WithSalt(byte[] salt)
    {
        _options.Salt = salt;
        return this;
    }

    /// <summary>
    /// Sets the OtherInfo as specified in SP 800-56A.
    /// </summary>
    /// <param name="otherInfo">The OtherInfo data.</param>
    /// <returns>The builder instance for chaining.</returns>
    public Sp80056COptionsBuilder WithOtherInfo(byte[] otherInfo)
    {
        _options.OtherInfo = otherInfo;
        return this;
    }

    /// <summary>
    /// Configures the pipeline to use two-step KDF (extract-then-expand).
    /// </summary>
    /// <param name="extractionPrf">The PRF type for extraction.</param>
    /// <param name="expansionPrf">The PRF type for expansion.</param>
    /// <returns>The builder instance for chaining.</returns>
    public Sp80056COptionsBuilder UseTwoStepKdf(PrfType extractionPrf, PrfType expansionPrf)
    {
        _options.UseTwoStep = true;
        _options.ExtractionPrfType = extractionPrf;
        _options.ExpansionPrfType = expansionPrf;
        return this;
    }

    /// <summary>
    /// Configures the pipeline to use one-step KDF.
    /// </summary>
    /// <param name="prfType">The PRF type for the KDF.</param>
    /// <returns>The builder instance for chaining.</returns>
    public Sp80056COptionsBuilder UseOneStepKdf(PrfType prfType)
    {
        _options.UseTwoStep = false;
        _options.ExpansionPrfType = prfType;
        return this;
    }

    /// <summary>
    /// Sets the KDF mode for the expansion step.
    /// </summary>
    /// <param name="mode">The KDF mode.</param>
    /// <returns>The builder instance for chaining.</returns>
    public Sp80056COptionsBuilder WithKdfMode(KdfMode mode)
    {
        _options.KdfMode = mode;
        return this;
    }

    /// <summary>
    /// Sets the counter configuration for the KDF.
    /// </summary>
    /// <param name="counterLengthBits">The counter length in bits.</param>
    /// <param name="counterLocation">The counter location.</param>
    /// <returns>The builder instance for chaining.</returns>
    public Sp80056COptionsBuilder WithCounterConfiguration(int counterLengthBits, CounterLocation counterLocation)
    {
        _options.CounterLengthBits = counterLengthBits;
        _options.CounterLocation = counterLocation;
        return this;
    }

    /// <summary>
    /// Builds the Sp80056COptions instance.
    /// </summary>
    /// <returns>The configured Sp80056COptions instance.</returns>
    public Sp80056COptions Build()
    {
        if (string.IsNullOrEmpty(_options.Label))
            throw new InvalidOperationException("Label must be specified");
        
        if (_options.OutputLengthInBits <= 0)
            throw new InvalidOperationException("Output length must be specified");

        return _options;
    }
}
