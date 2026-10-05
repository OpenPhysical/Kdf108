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
///     Contains unit tests for validating the functionality of the Counter Mode Key Derivation Function (KDF)
///     based on Response (Rsp) vector test cases.
/// </summary>
/// <remarks>
///     The class utilizes NUnit framework to provide comprehensive test coverage to ensure the accuracy
///     and reliability of the Counter Mode KDF implementation. It works with predefined test vector
///     configurations loaded dynamically for each test case.
/// </remarks>
[TestFixture]
[Category("CAVP-SP800-108")]
[Category("LongRunning")]
[Parallelizable(ParallelScope.All)]
// Loads the NIST SP 800-108 RSP File Test Vectors
public class RspVectorCounterModeTests
{
    /// <summary>
    ///     Generates a set of test vectors for testing KDF Counter Mode functionality
    ///     using the specified RSP (Response File) input.
    /// </summary>
    /// <returns>
    ///     An enumerable collection of test case data, where each case contains
    ///     a test vector with specific configurations such as PRF type, counter location,
    ///     output length, and other relevant parameters.
    /// </returns>
    private static IEnumerable<TestCaseData> GetRspVectors()
    {
        var filePath = GetTestVectorPath("KDFCTR_gen.rsp");
        IEnumerable<KdfTestVectorLoader.KdfTestVector> vectors =
            KdfTestVectorLoader.LoadCounterModeVectors(filePath);

        foreach (KdfTestVectorLoader.KdfTestVector vector in vectors)
        {
            yield return new TestCaseData(vector)
                .SetName(
                    $"KDF_CTR_{vector.PrfType}_{vector.CounterLocation}_{vector.RlenBits}bits_Vector{vector.Count:D4}");
        }
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

    /// <summary>
    ///     Validates that the derived key matches the expected output for a given test vector in the context of counter mode
    ///     KDF testing.
    /// </summary>
    /// <param name="vector">
    ///     A KDF test vector containing input parameters such as the key (Ki), PRF type, counter location, counter length in
    ///     bits (RLenBits),
    ///     fixed input data or split input data, the desired output length in bits (LBits), and the expected output key (Ko).
    /// </param>
    [Test]
    [TestCaseSource(nameof(GetRspVectors))]
    public void DeriveKey_FromRspVector_ProducesExpectedOutput(KdfTestVectorLoader.KdfTestVector vector)
    {
        CounterModeKdf kdf = new();
        byte[] output;


        if (vector is
            {
                CounterLocation: CounterLocation.MiddleFixed, DataBeforeCounter: not null, DataAfterCounter: not null
            })
        {
            // Use the special method for middle counter placement
            output = kdf.DeriveWithSplitFixedInput(
                vector.Ki,
                vector.DataBeforeCounter!,
                vector.DataAfterCounter!,
                vector.LBits,
                new KdfOptions
                {
                    PrfType = vector.PrfType, // Use the PRF type from the test vector
                    CounterLengthBits = vector.RlenBits,
                    UseCounter = true,
                    MaxBitsAllowed = vector.LBits
                });
        }
        else if (vector.FixedInput != null)
        {
            // Use the standard method for before/after fixed input data
            output = kdf.DeriveWithFixedInput(
                vector.Ki,
                vector.FixedInput!,
                vector.LBits,
                new KdfOptions
                {
                    PrfType = vector.PrfType, // Use the PRF type from the test vector
                    CounterLengthBits = vector.RlenBits,
                    UseCounter = true,
                    CounterLocation = vector.CounterLocation,
                    MaxBitsAllowed = vector.LBits
                });
        }
        else
        {
            return;
        }

        if (vector.CounterLocation != CounterLocation.MiddleFixed)
        {
            // Calculate what the input to the PRF would be for the first block
            byte[] expectedCounter = CounterUtilities.CreateCounter(1, vector.RlenBits);

            using MemoryStream stream = new();
            using BinaryWriter writer = new(stream);

            if (vector.CounterLocation == CounterLocation.BeforeFixed)
            {
                writer.Write(expectedCounter);
                writer.Write(vector.FixedInput!);
            }
            else
            {
                writer.Write(vector.FixedInput!);
                writer.Write(expectedCounter);
            }
        }

        Assert.That(output, Is.EqualTo(vector.Ko),
            $"Vector {vector.Count} failed with PRF={vector.PrfType}, CtrlLoc={vector.CounterLocation}, Rlen={vector.RlenBits}.");
    }

}
