// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;
using System.Linq;
using System.Text;
using FluentValidation;
using Kdf108.Domain.Kdf;
using Kdf108.Internal;

#endregion

namespace Kdf108.Test.Kdf;

/// <summary>
///     Represents a test suite designed to validate the behavior, edge cases, and compliance of the Counter Mode
///     implementation of the NIST SP 800-108 Key Derivation Function (KDF). This class includes tests covering
///     correctness, determinism, input validation, and scenarios for expected failures.
/// </summary>
[TestFixture]
[Parallelizable(ParallelScope.All)]
public class CounterModeKdfTests
{
    /// <summary>
    ///     Represents the static base key used as the initial key derivation key (KDK)
    ///     for testing the NIST SP 800-108 Key Derivation Function (KDF) in Counter Mode.
    /// </summary>
    /// <remarks>
    ///     The <c>s_baseKey</c> is defined as a hexadecimal byte array and serves as
    ///     the root key material for the key derivation process in test scenarios.
    ///     It remains constant across the test cases to ensure repeatability and
    ///     deterministic results during validation.
    /// </remarks>
    private static readonly byte[] s_baseKey = ConvertCompat.FromHexString("00112233445566778899AABBCCDDEEFF");

    /// <summary>
    ///     Represents the label used within the Key Derivation Function (KDF) process
    ///     to personalize or scope derived keys. It helps ensure distinct output for
    ///     different application contexts and use cases by introducing additional
    ///     variability into the derivation process.
    /// </summary>
    private const string Label = "TestLabel";

    /// <summary>
    ///     A static, readonly byte array used as the context parameter in
    ///     the key derivation process within tests for the NIST SP 800-108
    ///     Key Derivation Function (KDF) in Counter Mode.
    ///     The context typically represents application-specific information
    ///     and assists in ensuring uniqueness and scope isolation of derived
    ///     keys. This value is represented in these tests as a UTF-8 encoded string.
    /// </summary>
    private static readonly byte[] s_context = "Vault:1|Box:2|Item:3".ToUtf8();


    /// <summary>
    ///     Provides the default configuration settings for the Key Derivation Function (KDF) in Counter Mode.
    /// </summary>
    /// <remarks>
    ///     This property initializes and returns a pre-configured <see cref="KdfOptions" />
    ///     instance with a set of default options:
    ///     - Pseudo-random function type: HmacSha256.
    ///     - Counter length in bits: 32.
    ///     - Use of counter: Enabled.
    /// </remarks>
    private static KdfOptions DefaultOptions => new()
    {
        PrfType = PrfType.HmacSha256,
        CounterLengthBits = 32,
        UseCounter = true
    };

    /// <summary>
    ///     Validates that the derived key has the expected length.
    /// </summary>
    /// <param name="length">
    ///     The desired length of the derived key in bytes. Must be a positive integer.
    /// </param>
    [Test]
    [TestCase(16)]
    [TestCase(32)]
    [TestCase(64)]
    [TestCase(128)]
    public void DeriveKey_ReturnsExpectedLength(int length)
    {
        byte[] derived = KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, s_context, length * 8, DefaultOptions);
        Assert.That(derived, Has.Length.EqualTo(length));
    }

    /// <summary>
    ///     Verifies that the key derivation method produces a deterministic result
    ///     given the same base key, label, context, output length, and key derivation options.
    ///     Ensures that identical inputs will consistently result in the same output,
    ///     confirming compliance with the deterministic nature of the key derivation function.
    /// </summary>
    [Test]
    public void DeriveKey_ReturnsDeterministicResult()
    {
        byte[] k1 = KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, s_context, 256, DefaultOptions);
        byte[] k2 = KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, s_context, 256, DefaultOptions);
        Assert.That(k1, Is.EqualTo(k2));
    }

    /// <summary>
    ///     Tests that deriving keys with different labels produces distinct outputs.
    ///     This ensures that the label input to the key derivation function
    ///     properly influences the derived result and generates unique keys based
    ///     on different labels.
    /// </summary>
    /// <param name="labelA">The first label used for key derivation.</param>
    /// <param name="labelB">The second label used for key derivation.</param>
    [TestCase("Label-A", "Label-B")]
    [TestCase("abc", "xyz")]
    public void DeriveKey_WithDifferentLabel_ProducesDifferentOutput(string labelA, string labelB)
    {
        byte[] k1 = KdfEngine.Derive(KdfMode.Counter, s_baseKey, labelA, s_context, 256, DefaultOptions);
        byte[] k2 = KdfEngine.Derive(KdfMode.Counter, s_baseKey, labelB, s_context, 256, DefaultOptions);
        Assert.That(k1, Is.Not.EqualTo(k2));
    }

    /// <summary>
    ///     Verifies that the key derivation function produces different outputs
    ///     when provided with different context strings.
    /// </summary>
    /// <param name="ctxA">The first context string used in key derivation.</param>
    /// <param name="ctxB">The second context string used in key derivation.</param>
    [TestCase("Context1", "Context2")]
    [TestCase("Vault:A", "Vault:B")]
    public void DeriveKey_WithDifferentContext_ProducesDifferentOutput(string ctxA, string ctxB)
    {
        byte[] c1 = Encoding.UTF8.GetBytes(ctxA);
        byte[] c2 = Encoding.UTF8.GetBytes(ctxB);

        byte[] k1 = KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, c1, 256, DefaultOptions);
        byte[] k2 = KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, c2, 256, DefaultOptions);
        Assert.That(k1, Is.Not.EqualTo(k2));
    }

    /// <summary>
    ///     Validates that the key derivation process produces different output values
    ///     when requested with varying output lengths.
    /// </summary>
    /// <remarks>
    ///     This test ensures that the key derivation function generates output of the specified length
    ///     and that shorter outputs represent unique segments, distinct from longer outputs.
    /// </remarks>
    [Test]
    public void DeriveKey_WithDifferentOutputLengths_ProducesDifferentOutputs()
    {
        byte[] full = KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, s_context, 512, DefaultOptions);
        byte[] half = KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, s_context, 256, DefaultOptions);

        Assert.Multiple(() =>
        {
            Assert.That(full, Has.Length.EqualTo(64));
            Assert.That(half, Has.Length.EqualTo(32));
            Assert.That(half, Is.Not.EqualTo(new ArraySegment<byte>(full, 0, 32).ToArray()));
        });
    }

    /// <summary>
    ///     Validates that the <see cref="KdfEngine.Derive" /> method throws a <see cref="ValidationException" />
    ///     when the provided base key (kdk) is null while using the Counter mode.
    /// </summary>
    /// <remarks>
    ///     This test ensures that the key derivation function correctly rejects null base key input,
    ///     preventing invalid operations and safeguarding against potential issues in the key derivation process.
    /// </remarks>
    /// <exception cref="ValidationException">
    ///     Thrown when the base key (kdk) is null.
    /// </exception>
    [Test]
    public void DeriveKey_ThrowsOnNullBaseKey() =>
        Assert.Throws<ValidationException>(() =>
            KdfEngine.Derive(KdfMode.Counter, null!, Label, s_context, 256, DefaultOptions));

    /// <summary>
    ///     Validates that the key derivation function (KDF) throws a <see cref="ValidationException" />
    ///     when a null or empty string is provided as the label input.
    /// </summary>
    /// <remarks>
    ///     The test ensures that the label parameter is mandatory as per the requirements of
    ///     the NIST SP 800-108 Key Derivation Function (KDF) in Counter Mode.
    /// </remarks>
    /// <exception cref="ValidationException">
    ///     Thrown when a null or empty string is passed as the label input during the KDF process.
    /// </exception>
    [Test]
    public void DeriveKey_ThrowsOnNullLabel() =>
        Assert.Throws<ValidationException>(static () =>
            KdfEngine.Derive(KdfMode.Counter, s_baseKey, null!, s_context, 256, DefaultOptions));

    /// <summary>
    ///     Validates that the key derivation function throws a <see cref="ValidationException" />
    ///     when provided with a null context parameter.
    /// </summary>
    /// <remarks>
    ///     This test ensures that the Key Derivation Function (KDF) enforces its parameter
    ///     validation rules by rejecting a null value for the context parameter. A valid
    ///     implementation of the function must guarantee input integrity, as improper handling
    ///     can lead to undefined behavior or compromised security properties.
    /// </remarks>
    /// <exception cref="FluentValidation.ValidationException">
    ///     Thrown if the context parameter is null during the key derivation process.
    /// </exception>
    [Test]
    public void DeriveKey_ThrowsOnNullContext() =>
        Assert.Throws<ValidationException>(() =>
            KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, null!, 256, DefaultOptions));

    /// <summary>
    ///     Validates that the Key Derivation Function (KDF) throws a ValidationException
    ///     if a non-positive output length is provided (zero or negative values).
    /// </summary>
    /// <exception cref="FluentValidation.ValidationException">
    ///     Thrown if the output length is zero or negative, as these are invalid parameters
    ///     for key derivation.
    /// </exception>
    [Test]
    public void DeriveKey_ThrowsOnNonPositiveLength()
    {
        Assert.Throws<ValidationException>(() =>
            KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, s_context, 0, DefaultOptions));
        Assert.Throws<ValidationException>(() =>
            KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, s_context, -1, DefaultOptions));
    }

    /// <summary>
    ///     Validates that the key derivation function in Counter Mode does not encounter overflow
    ///     when the desired output spans multiple hash blocks (e.g., multiple iterations of the
    ///     hash function are needed to satisfy the requested output length).
    /// </summary>
    /// <remarks>
    ///     This test ensures that the implementation can handle cases where key material must be
    ///     derived across several iterations, and the resulting output length matches the expectation.
    ///     Specifically, it verifies that no overflow or related defects occur while the function
    ///     handles requests requiring three or more SHA-256 blocks.
    /// </remarks>
    /// <exception cref="AssertionException">
    ///     Thrown if the length of the derived key material does not correspond to the expected number of bytes
    ///     for the requested output length in bits.
    /// </exception>
    [Test]
    public void DeriveKey_DoesNotOverflowForMultipleBlocks()
    {
        const int lengthBits = 3 * 256; // 3 blocks of SHA256 in bits
        byte[] output = KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, s_context, lengthBits, DefaultOptions);
        Assert.That(output, Has.Length.EqualTo(lengthBits / 8));
    }

    /// <summary>
    ///     Validates that the key derivation function (KDF) throws a <see cref="ValidationException" />
    ///     when attempting to derive a key with an unreasonably large output length.
    /// </summary>
    /// <remarks>
    ///     The test ensures that the implementation has safeguards in place to prevent
    ///     excessively large output requirements that could cause performance degradation,
    ///     memory issues, or system instability. Specifically, passing <see cref="int.MaxValue" />
    ///     as the output length should trigger a validation error.
    /// </remarks>
    /// <exception cref="ValidationException">
    ///     Thrown when the requested output length exceeds the configured maximum limit.
    /// </exception>
    [Test]
    public void DeriveKey_RejectsRidiculouslyLargeLengths()
    {
        ValidationException? ex = Assert.Throws<ValidationException>(static () =>
            KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, s_context, int.MaxValue, DefaultOptions));
        Assert.That(ex!.Message, Does.Contain("exceeds configured maximum"));
    }

    /// <summary>
    ///     Validates the deterministic functionality of the NIST SP 800-108 Key Derivation Function
    ///     in Counter Mode by comparing the derived key to a known correct output vector.
    /// </summary>
    /// <remarks>
    ///     This test ensures that the key derivation process produces consistent and correct
    ///     results matching predefined expected values for a fixed configuration, enhancing
    ///     confidence in the implementation's correctness.
    /// </remarks>
    /// <exception cref="AssertionException">
    ///     Thrown when the derived key does not match the expected known vector, indicating
    ///     a potential flaw in the implementation.
    /// </exception>
    [Test]
    public void DeriveKey_KnownVectorValidation()
    {
        byte[] expected =
            ConvertCompat.FromHexString("D39D601E90C9B0CB45B2E841313D0D4172A1B3C52AA8D049302B401AEB9EDFB6");
        byte[] actual = KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, s_context, 256, DefaultOptions);
        Assert.That(actual, Is.EqualTo(expected));
    }

    /// <summary>
    ///     Ensures that output key lengths exceeding 1 KB are rejected during the
    ///     derivation process. Verifies that an appropriate <see cref="ValidationException" />
    ///     is thrown when attempting to derive a key with a length greater than 1024 bytes.
    /// </summary>
    /// <remarks>
    ///     This test enforces the maximum allowable output length for the key derivation
    ///     process using the NIST SP 800-108 Counter Mode KDF. Exceeding this limit is
    ///     configured intentionally to prevent impractical or unsupported use cases.
    /// </remarks>
    /// <exception cref="ValidationException">
    ///     Thrown when the requested output length exceeds the configured maximum (1 KB).
    /// </exception>
    [Test]
    public void DeriveKey_RejectsOutputLargerThan1Kb()
    {
        ValidationException? ex = Assert.Throws<ValidationException>(() =>
            KdfEngine.Derive(KdfMode.Counter, s_baseKey, Label, s_context, 8192 + 1, DefaultOptions));

        Assert.That(ex, Is.Not.Null);
        Assert.That(ex!.Message, Does.Contain("exceeds configured maximum"));
    }
}
