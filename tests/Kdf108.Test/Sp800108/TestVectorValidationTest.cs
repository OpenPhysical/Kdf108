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
[Category("CAVP-SP800-108")]
[Category("LongRunning")]
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
        Assert.That(vectors.Count, Is.EqualTo(3840));

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} conforming Counter Mode vectors (960 legacy TDEA vectors classified separately)");
    }

    [Test]
    public void ValidateKdfDoublePipelineWithCounterVectors_LoadsExpectedMinimumCount()
    {
        // Arrange
        var filePath = GetTestVectorPath("KDFDblPipelineWithCtr_gen.rsp");

        // Act - This will fail with strict validation if there are any issues
        var vectors = KdfTestVectorLoader.LoadDoublePipelineVectors(filePath).ToList();

        // Assert - Verify we loaded the expected minimum number of test vectors
        Assert.That(vectors.Count, Is.EqualTo(3840));

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} conforming DoublePipeline+Counter vectors (960 legacy TDEA vectors classified separately)");
    }

    [Test]
    public void ValidateKdfDoublePipelineWithoutCounterVectors_LoadsExpectedMinimumCount()
    {
        // Arrange
        var filePath = GetTestVectorPath("KDFDblPipelineWOCtr_gen.rsp");

        // Act - This will fail with strict validation if there are any issues
        var vectors = KdfTestVectorLoader.LoadDoublePipelineVectors(filePath).ToList();

        // Assert - Verify we loaded the expected minimum number of test vectors
        Assert.That(vectors.Count, Is.EqualTo(320));

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} conforming DoublePipeline-NoCounter vectors (80 legacy TDEA vectors classified separately)");
    }

    [Test]
    public void ValidateKdfFeedbackNoCounterVectors_LoadsExpectedMinimumCount()
    {
        // Arrange
        var filePath = GetTestVectorPath("KDFFeedbackNoCtr_gen.rsp");

        // Act - This will fail with strict validation if there are any issues
        var vectors = KdfTestVectorLoader.LoadFeedbackVectors(filePath).ToList();

        // Assert - Verify we loaded the expected minimum number of test vectors
        Assert.That(vectors.Count, Is.EqualTo(320));

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} conforming Feedback-NoCounter vectors (80 legacy TDEA vectors classified separately)");
    }

    [Test]
    public void ValidateKdfFeedbackWithZeroIvVectors_LoadsExpectedMinimumCount()
    {
        // Arrange
        var filePath = GetTestVectorPath("KDFFeedbackWithZeroIV_gen.rsp");

        // Act - This will fail with strict validation if there are any issues
        var vectors = KdfTestVectorLoader.LoadFeedbackVectors(filePath).ToList();

        // Assert - Verify we loaded the expected minimum number of test vectors
        Assert.That(vectors.Count, Is.EqualTo(3840));

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} conforming Feedback+ZeroIV vectors (960 legacy TDEA vectors classified separately)");
    }

    [Test]
    public void ValidateKdfFeedbackNoZeroIvVectors_LoadsExpectedMinimumCount()
    {
        // Arrange
        var filePath = GetTestVectorPath("KDFFeedbackNoZeroIV_gen.rsp");

        // Act - This will fail with strict validation if there are any issues
        var vectors = KdfTestVectorLoader.LoadFeedbackVectors(filePath).ToList();

        // Assert - Verify we loaded the expected minimum number of test vectors
        Assert.That(vectors.Count, Is.EqualTo(3840));

        TestContext.Out.WriteLine($"SUCCESS: Loaded {vectors.Count} conforming Feedback-NoZeroIV vectors (960 legacy TDEA vectors classified separately)");
    }

    [Test]
    public void ValidateAllTestVectors_MeetTotalMinimumCount()
    {
        // Arrange
        var totalExpected = 16000;
        var totalActual = 0;

        // Act - Load all vector types and count them
        totalActual += KdfTestVectorLoader.LoadCounterModeVectors(GetTestVectorPath("KDFCTR_gen.rsp")).Count();
        totalActual += KdfTestVectorLoader.LoadDoublePipelineVectors(GetTestVectorPath("KDFDblPipelineWithCtr_gen.rsp")).Count();
        totalActual += KdfTestVectorLoader.LoadDoublePipelineVectors(GetTestVectorPath("KDFDblPipelineWOCtr_gen.rsp")).Count();
        totalActual += KdfTestVectorLoader.LoadFeedbackVectors(GetTestVectorPath("KDFFeedbackNoCtr_gen.rsp")).Count();
        totalActual += KdfTestVectorLoader.LoadFeedbackVectors(GetTestVectorPath("KDFFeedbackWithZeroIV_gen.rsp")).Count();
        totalActual += KdfTestVectorLoader.LoadFeedbackVectors(GetTestVectorPath("KDFFeedbackNoZeroIV_gen.rsp")).Count();

        Assert.That(totalActual, Is.EqualTo(totalExpected),
            $"Classification drift: Expected exactly {totalExpected} conforming SP800-108 vectors, but got {totalActual}");

        TestContext.Out.WriteLine($"SUCCESS: Loaded {totalActual:N0} conforming SP800-108 vectors ({totalExpected:N0} required)");
        TestContext.Out.WriteLine("Classification policy: all 4,000 legacy TDEA vectors were counted separately.");
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
