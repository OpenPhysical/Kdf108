// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System.IO;
using System.Linq;

namespace Kdf108.Test.Sp800108;

/// <summary>
/// Zero-skip validation test to verify our strict loading policy is working correctly.
/// This test ensures that all test vectors are properly loaded and that we meet minimum count requirements.
/// </summary>
[TestFixture]
[Category("Unit")]
public class TestVectorValidationTest
{
    [Test]
    public void ValidateKdfCounterModeVectors_LoadsExpectedMinimumCount()
    {
        // Arrange
        var filePath = GetTestVectorPath("KDFCTR_gen.rsp");

        // Act - This will fail with strict validation if there are any issues
        var vectors = KdfTestVectorLoader.LoadCounterModeVectors(filePath).ToList();

        // Assert - Verify we loaded the expected minimum number of test vectors
        Assert.That(vectors.Count, Is.GreaterThanOrEqualTo(4800),
            $"Zero-skip policy violation: Expected at least 4800 Counter Mode test vectors, but got {vectors.Count}");

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} Counter Mode test vectors (≥4800 required)");
    }

    [Test]
    public void ValidateKdfDoublePipelineWithCounterVectors_LoadsExpectedMinimumCount()
    {
        // Arrange
        var filePath = GetTestVectorPath("KDFDblPipelineWithCtr_gen.rsp");

        // Act - This will fail with strict validation if there are any issues
        var vectors = KdfTestVectorLoader.LoadDoublePipelineVectors(filePath).ToList();

        // Assert - Verify we loaded the expected minimum number of test vectors
        Assert.That(vectors.Count, Is.GreaterThanOrEqualTo(4800),
            $"Zero-skip policy violation: Expected at least 4800 DoublePipeline+Counter test vectors, but got {vectors.Count}");

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} DoublePipeline+Counter test vectors (≥4800 required)");
    }

    [Test]
    public void ValidateKdfDoublePipelineWithoutCounterVectors_LoadsExpectedMinimumCount()
    {
        // Arrange
        var filePath = GetTestVectorPath("KDFDblPipelineWOCtr_gen.rsp");

        // Act - This will fail with strict validation if there are any issues
        var vectors = KdfTestVectorLoader.LoadDoublePipelineVectors(filePath).ToList();

        // Assert - Verify we loaded the expected minimum number of test vectors
        Assert.That(vectors.Count, Is.GreaterThanOrEqualTo(400),
            $"Zero-skip policy violation: Expected at least 400 DoublePipeline-NoCounter test vectors, but got {vectors.Count}");

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} DoublePipeline-NoCounter test vectors (≥400 required)");
    }

    [Test]
    public void ValidateKdfFeedbackNoCounterVectors_LoadsExpectedMinimumCount()
    {
        // Arrange
        var filePath = GetTestVectorPath("KDFFeedbackNoCtr_gen.rsp");

        // Act - This will fail with strict validation if there are any issues
        var vectors = KdfTestVectorLoader.LoadFeedbackVectors(filePath).ToList();

        // Assert - Verify we loaded the expected minimum number of test vectors
        Assert.That(vectors.Count, Is.GreaterThanOrEqualTo(400),
            $"Zero-skip policy violation: Expected at least 400 Feedback-NoCounter test vectors, but got {vectors.Count}");

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} Feedback-NoCounter test vectors (≥400 required)");
    }

    [Test]
    public void ValidateKdfFeedbackWithZeroIvVectors_LoadsExpectedMinimumCount()
    {
        // Arrange
        var filePath = GetTestVectorPath("KDFFeedbackWithZeroIV_gen.rsp");

        // Act - This will fail with strict validation if there are any issues
        var vectors = KdfTestVectorLoader.LoadFeedbackVectors(filePath).ToList();

        // Assert - Verify we loaded the expected minimum number of test vectors
        Assert.That(vectors.Count, Is.GreaterThanOrEqualTo(4800),
            $"Zero-skip policy violation: Expected at least 4800 Feedback+ZeroIV test vectors, but got {vectors.Count}");

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} Feedback+ZeroIV test vectors (≥4800 required)");
    }

    [Test]
    public void ValidateKdfFeedbackNoZeroIvVectors_LoadsExpectedMinimumCount()
    {
        // Arrange
        var filePath = GetTestVectorPath("KDFFeedbackNoZeroIV_gen.rsp");

        // Act - This will fail with strict validation if there are any issues
        var vectors = KdfTestVectorLoader.LoadFeedbackVectors(filePath).ToList();

        // Assert - Verify we loaded the expected minimum number of test vectors
        Assert.That(vectors.Count, Is.GreaterThanOrEqualTo(4800),
            $"Zero-skip policy violation: Expected at least 4800 Feedback-NoZeroIV test vectors, but got {vectors.Count}");

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} Feedback-NoZeroIV test vectors (≥4800 required)");
    }

    [Test]
    public void ValidateAllTestVectors_MeetTotalMinimumCount()
    {
        // Arrange
        var totalExpected = 4800 + 4800 + 400 + 400 + 4800 + 4800; // 20,000 total
        var totalActual = 0;

        // Act - Load all vector types and count them
        totalActual += KdfTestVectorLoader.LoadCounterModeVectors(GetTestVectorPath("KDFCTR_gen.rsp")).Count();
        totalActual += KdfTestVectorLoader.LoadDoublePipelineVectors(GetTestVectorPath("KDFDblPipelineWithCtr_gen.rsp")).Count();
        totalActual += KdfTestVectorLoader.LoadDoublePipelineVectors(GetTestVectorPath("KDFDblPipelineWOCtr_gen.rsp")).Count();
        totalActual += KdfTestVectorLoader.LoadFeedbackVectors(GetTestVectorPath("KDFFeedbackNoCtr_gen.rsp")).Count();
        totalActual += KdfTestVectorLoader.LoadFeedbackVectors(GetTestVectorPath("KDFFeedbackWithZeroIV_gen.rsp")).Count();
        totalActual += KdfTestVectorLoader.LoadFeedbackVectors(GetTestVectorPath("KDFFeedbackNoZeroIV_gen.rsp")).Count();

        // Assert - We should have AT LEAST 20,000 test vectors total
        Assert.That(totalActual, Is.GreaterThanOrEqualTo(totalExpected),
            $"Zero-skip policy violation: Expected at least {totalExpected} total SP800-108 test vectors, but got {totalActual}");

        TestContext.Out.WriteLine($"SUCCESS: Loaded {totalActual:N0} total SP800-108 test vectors (≥{totalExpected:N0} required)");
        TestContext.Out.WriteLine("Zero-skip policy: ✅ All test vectors loaded successfully!");
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
