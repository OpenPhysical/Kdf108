// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;

namespace Kdf108.Test.Sp800108;

/// <summary>
///     Test suite for validating the Feedback Mode KDF implementation
///     using NIST SP 800-108 test vectors.
/// </summary>
[TestFixture]
[Category("CAVP-SP800-108")]
[Category("LongRunning")]
[Parallelizable(ParallelScope.All)]
public class RspVectorFeedbackTests
{
    /// <summary>
    ///     Generates test cases from KDF feedback mode test vectors with no counter.
    /// </summary>
    /// <returns>Test cases for validation.</returns>
    private static IEnumerable<TestCaseData> GetRspVectorsNoCounter()
    {
        IEnumerable<KdfTestVectorLoader.KdfTestVector> vectors =
            KdfTestVectorLoader.LoadFeedbackVectors(GetTestVectorPath("KDFFeedbackNoCtr_gen.rsp"));

        foreach (KdfTestVectorLoader.KdfTestVector vector in vectors)
        {
            yield return new TestCaseData(vector)
                .SetName(
                    $"KDF_Feedback_NoCtr_{vector.PrfType}_Vector{vector.Count:D4}");
        }
    }

    /// <summary>
    ///     Generates test cases from KDF feedback mode test vectors with counter and allowing zero-length IV.
    /// </summary>
    /// <returns>Test cases for validation.</returns>
    private static IEnumerable<TestCaseData> GetRspVectorsWithZeroIv()
    {
        IEnumerable<KdfTestVectorLoader.KdfTestVector> vectors =
            KdfTestVectorLoader.LoadFeedbackVectors(GetTestVectorPath("KDFFeedbackWithZeroIV_gen.rsp"));

        foreach (KdfTestVectorLoader.KdfTestVector vector in vectors)
        {
            yield return new TestCaseData(vector)
                .SetName(
                    $"KDF_Feedback_WithZeroIV_{vector.PrfType}_{vector.CounterLocation}_{vector.RlenBits}bits_Vector{vector.Count:D4}");
        }
    }

    /// <summary>
    ///     Generates test cases from KDF feedback mode test vectors with counter and not allowing zero-length IV.
    /// </summary>
    /// <returns>Test cases for validation.</returns>
    private static IEnumerable<TestCaseData> GetRspVectorsNoZeroIv()
    {
        IEnumerable<KdfTestVectorLoader.KdfTestVector> vectors =
            KdfTestVectorLoader.LoadFeedbackVectors(GetTestVectorPath("KDFFeedbackNoZeroIV_gen.rsp"));

        foreach (KdfTestVectorLoader.KdfTestVector vector in vectors)
        {
            yield return new TestCaseData(vector)
                .SetName(
                    $"KDF_Feedback_NoZeroIV_{vector.PrfType}_{vector.CounterLocation}_{vector.RlenBits}bits_Vector{vector.Count:D4}");
        }
    }

    /// <summary>
    ///     Validates that the derived key matches the expected output for test vectors with no counter.
    /// </summary>
    /// <param name="vector">The test vector to validate against.</param>
    [Test]
    [TestCaseSource(nameof(GetRspVectorsNoCounter))]
    public void DeriveKey_FromRspVectorNoCounter_ProducesExpectedOutput(KdfTestVectorLoader.KdfTestVector vector)
    {
        // Arrange
        FeedbackModeKdf kdf = new(false);


        // Act
        byte[] output = kdf.DeriveWithFixedInput(
            vector.Ki,
            vector.FixedInput!,
            vector.Iv,
            vector.LBits,
            new KdfOptions { PrfType = vector.PrfType, UseCounter = false, MaxBitsAllowed = vector.LBits });

        // Assert
        Assert.That(output, Is.EqualTo(vector.Ko),
            $"Vector {vector.Count} failed with PRF={vector.PrfType}.");
    }

    /// <summary>
    ///     Validates that the derived key matches the expected output for test vectors with counter and allowing zero-length
    ///     IV.
    /// </summary>
    /// <param name="vector">The test vector to validate against.</param>
    [Test]
    [TestCaseSource(nameof(GetRspVectorsWithZeroIv))]
    public void DeriveKey_FromRspVectorWithZeroIV_ProducesExpectedOutput(KdfTestVectorLoader.KdfTestVector vector)
    {
        // Arrange
        FeedbackModeKdf kdf = new(true);


        // Act
        byte[] output = kdf.DeriveWithFixedInput(
            vector.Ki,
            vector.FixedInput!,
            vector.Iv, // Could be empty
            vector.LBits,
            new KdfOptions
            {
                PrfType = vector.PrfType,
                CounterLengthBits = vector.RlenBits,
                UseCounter = true,
                CounterLocation = vector.CounterLocation,
                MaxBitsAllowed = vector.LBits
            });

        // Assert
        Assert.That(output, Is.EqualTo(vector.Ko),
            $"Vector {vector.Count} failed with PRF={vector.PrfType}, CtrlLoc={vector.CounterLocation}, Rlen={vector.RlenBits}.");
    }

    /// <summary>
    ///     Validates that the derived key matches the expected output for test vectors with counter and not allowing
    ///     zero-length IV.
    /// </summary>
    /// <param name="vector">The test vector to validate against.</param>
    [Test]
    [TestCaseSource(nameof(GetRspVectorsNoZeroIv))]
    public void DeriveKey_FromRspVectorNoZeroIV_ProducesExpectedOutput(KdfTestVectorLoader.KdfTestVector vector)
    {
        // Arrange
        FeedbackModeKdf kdf = new(true);


        // Act
        // IV should never be null or empty in these test vectors
        if (vector.Iv == null || vector.Iv.Length == 0)
        {
            Assert.Fail("Test vector has null or empty IV when zero-length IV is not allowed");
        }

        byte[] output = kdf.DeriveWithFixedInput(
            vector.Ki,
            vector.FixedInput!,
            vector.Iv,
            vector.LBits,
            new KdfOptions
            {
                PrfType = vector.PrfType,
                CounterLengthBits = vector.RlenBits,
                UseCounter = true,
                CounterLocation = vector.CounterLocation,
                MaxBitsAllowed = vector.LBits
            });

        // Assert
        Assert.That(output, Is.EqualTo(vector.Ko),
            $"Vector {vector.Count} failed with PRF={vector.PrfType}, CtrlLoc={vector.CounterLocation}, Rlen={vector.RlenBits}.");
    }

    private static string GetTestVectorPath(string fileName)
    {
        // Find the project root by looking for the .csproj file
        var currentDir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (currentDir != null && !currentDir.GetFiles("*.csproj").Any())
        {
            currentDir = currentDir.Parent;
        }

        if (currentDir == null)
        {
            throw new DirectoryNotFoundException("Test validation failed: Could not find project root directory for SP800-108 tests!");
        }

        return Path.Combine(currentDir.FullName, "res", "vectors", "SP800-108", fileName);
    }
}
