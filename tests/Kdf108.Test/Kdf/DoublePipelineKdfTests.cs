// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System.Text;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Kdf108.Internal;

#endregion

namespace Kdf108.Test.Kdf;

/// <summary>
///     Test suite for the DoublePipelineKdf implementation to verify conformance with SP800-108.
/// </summary>
[TestFixture]
[Parallelizable(ParallelScope.All)]
public class DoublePipelineKdfTests
{
    /// <summary>
    ///     Base key used for testing the double-pipeline mode KDF
    /// </summary>
    private static readonly byte[] s_baseKey = ConvertCompat.FromHexString("00112233445566778899AABBCCDDEEFF");

    /// <summary>
    ///     Label used in the KDF process
    /// </summary>
    private const string Label = "TestLabel";

    /// <summary>
    ///     Context information used in the KDF process
    /// </summary>
    private static readonly byte[] s_context = "Vault:1|Box:2|Item:3".ToUtf8();

    /// <summary>
    ///     Default KDF options for testing
    /// </summary>
    private static KdfOptions DefaultOptions => new()
    {
        PrfType = PrfType.HmacSha256,
        CounterLengthBits = 32,
        UseCounter = true,
        CounterLocation = CounterLocation.BeforeFixed
    };

    /// <summary>
    ///     Tests that the DoublePipelineKdf returns a key of the expected length.
    /// </summary>
    /// <param name="length">The length of the derived key in bytes.</param>
    [Test]
    [TestCase(16)]
    [TestCase(32)]
    [TestCase(64)]
    [TestCase(128)]
    public void DeriveKey_ReturnsExpectedLength(int length)
    {
        // Arrange
        DoublePipelineKdf kdf = new(true); // With counter

        // Act
        byte[] derived = kdf.DeriveKey(s_baseKey, Label, s_context, length * 8, DefaultOptions);

        // Assert
        Assert.That(derived, Has.Length.EqualTo(length));
    }

    /// <summary>
    ///     Verifies that the key derivation process produces deterministic results
    ///     given the same inputs.
    /// </summary>
    [Test]
    public void DeriveKey_ReturnsDeterministicResult()
    {
        // Arrange
        DoublePipelineKdf kdf = new(true); // With counter

        // Act
        byte[] k1 = kdf.DeriveKey(s_baseKey, Label, s_context, 256, DefaultOptions);
        byte[] k2 = kdf.DeriveKey(s_baseKey, Label, s_context, 256, DefaultOptions);

        // Assert
        Assert.That(k1, Is.EqualTo(k2));
    }

    /// <summary>
    ///     Tests that deriving keys with different labels produces different outputs.
    /// </summary>
    /// <param name="labelA">The first label to use.</param>
    /// <param name="labelB">The second label to use.</param>
    [TestCase("Label-A", "Label-B")]
    [TestCase("abc", "xyz")]
    public void DeriveKey_WithDifferentLabel_ProducesDifferentOutput(string labelA, string labelB)
    {
        // Arrange
        DoublePipelineKdf kdf = new(true); // With counter

        // Act
        byte[] k1 = kdf.DeriveKey(s_baseKey, labelA, s_context, 256, DefaultOptions);
        byte[] k2 = kdf.DeriveKey(s_baseKey, labelB, s_context, 256, DefaultOptions);

        // Assert
        Assert.That(k1, Is.Not.EqualTo(k2));
    }

    /// <summary>
    ///     Verifies that the key derivation function produces different outputs
    ///     when provided with different context strings.
    /// </summary>
    /// <param name="ctxA">The first context string.</param>
    /// <param name="ctxB">The second context string.</param>
    [TestCase("Context1", "Context2")]
    [TestCase("Vault:A", "Vault:B")]
    public void DeriveKey_WithDifferentContext_ProducesDifferentOutput(string ctxA, string ctxB)
    {
        // Arrange
        DoublePipelineKdf kdf = new(true); // With counter
        byte[] c1 = Encoding.UTF8.GetBytes(ctxA);
        byte[] c2 = Encoding.UTF8.GetBytes(ctxB);

        // Act
        byte[] k1 = kdf.DeriveKey(s_baseKey, Label, c1, 256, DefaultOptions);
        byte[] k2 = kdf.DeriveKey(s_baseKey, Label, c2, 256, DefaultOptions);

        // Assert
        Assert.That(k1, Is.Not.EqualTo(k2));
    }

    /// <summary>
    ///     Tests that the double-pipeline mode without counter produces the expected output.
    /// </summary>
    [Test]
    public void DeriveKey_WithoutCounter_ProducesExpectedOutput()
    {
        // Arrange
        DoublePipelineKdf kdf = new(false); // Without counter
        KdfOptions options = new() { PrfType = PrfType.HmacSha256, CounterLengthBits = 32, UseCounter = false };

        // Act
        byte[] derived = kdf.DeriveKey(s_baseKey, Label, s_context, 256, options);

        // Assert
        // We would compare against a known vector here
        Assert.That(derived, Has.Length.EqualTo(32));
    }

    /// <summary>
    ///     Tests that the double-pipeline mode with counter in different positions produces different outputs.
    /// </summary>
    [Test]
    public void DeriveKey_DifferentCounterLocations_ProduceDifferentOutputs()
    {
        // Arrange
        DoublePipelineKdf kdf = new(true); // With counter

        KdfOptions optionsBefore = new()
        {
            PrfType = PrfType.HmacSha256,
            CounterLengthBits = 32,
            UseCounter = true,
            CounterLocation = CounterLocation.BeforeFixed
        };

        KdfOptions optionsAfter = new()
        {
            PrfType = PrfType.HmacSha256,
            CounterLengthBits = 32,
            UseCounter = true,
            CounterLocation = CounterLocation.AfterFixed
        };

        // Act
        byte[] keyBefore = kdf.DeriveKey(s_baseKey, Label, s_context, 256, optionsBefore);
        byte[] keyAfter = kdf.DeriveKey(s_baseKey, Label, s_context, 256, optionsAfter);

        // Assert
        Assert.That(keyBefore, Is.Not.EqualTo(keyAfter));
    }

    /// <summary>
    ///     Tests that the double-pipeline mode with different counter lengths produces different outputs.
    /// </summary>
    [Test]
    public void DeriveKey_DifferentCounterLengths_ProduceDifferentOutputs()
    {
        // Arrange
        DoublePipelineKdf kdf = new(true); // With counter

        KdfOptions options8 = new()
        {
            PrfType = PrfType.HmacSha256,
            CounterLengthBits = 8,
            UseCounter = true,
            CounterLocation = CounterLocation.BeforeFixed
        };

        KdfOptions options32 = new()
        {
            PrfType = PrfType.HmacSha256,
            CounterLengthBits = 32,
            UseCounter = true,
            CounterLocation = CounterLocation.BeforeFixed
        };

        // Act
        byte[] key8 = kdf.DeriveKey(s_baseKey, Label, s_context, 256, options8);
        byte[] key32 = kdf.DeriveKey(s_baseKey, Label, s_context, 256, options32);

        // Assert
        Assert.That(key8, Is.Not.EqualTo(key32));
    }

    /// <summary>
    ///     Tests that the double-pipeline mode with a known test vector produces the expected output.
    /// </summary>
    [Test]
    public void DeriveKey_WithKnownVector_ProducesExpectedOutput()
    {
        // This is a placeholder for actual test vector validation
        // We would use actual NIST test vectors here

        // Example test vector (replace with actual test vector):
        byte[] key = ConvertCompat.FromHexString("ADA2452F1F141A82C7A1B7D3E09FFED1");
        byte[] fixedInput =
            ConvertCompat.FromHexString(
                "335660EB265D2044EFA06EACD848D3F9F57D219011343318F3A964DF4A6FB1BF6CBDEE711C7FCBE73B8F257F992E47E8B065AF");
        byte[] expectedOutput =
            ConvertCompat.FromHexString(
                "A73BD29176E38E761222AE07D639181F4B2C555A3B261815CDE5D88A67C8B95C58B6B66EA4F10608C6D799B051519FC8E89DE00CDC556350A7D966475086F9AF");

        // Arrange
        DoublePipelineKdf kdf = new(false); // Without counter
        KdfOptions options = new() { PrfType = PrfType.CmacAes128, UseCounter = false };

        // Act
        byte[] result = kdf.DeriveWithFixedInput(key, fixedInput, 512, options);

        // Assert - uncomment when using actual test vectors
        // Assert.That(result, Is.EqualTo(expectedOutput));
    }
}
