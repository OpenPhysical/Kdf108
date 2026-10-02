using System;
using System.IO;
using System.Linq;
using AwesomeAssertions;
using Kdf108.Domain.Sp80056A;
using Kdf108.Domain.Sp80056C;

namespace Kdf108.Test.Sp80056C;

[TestFixture]
[Category("Unit")]
[Category("TestVectors")]
public class Sp80056CTestVectorTests
{
    private string _testVectorPath;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        // Find the test vector file
        var currentDirectory = TestContext.CurrentContext.TestDirectory;
        var projectRoot = FindProjectRoot(currentDirectory);
        _testVectorPath = Path.Combine(projectRoot, "tests", "Kdf108.Test", "res", "vectors", "SP800-56C", "test_vectors.txt");
        
        if (!File.Exists(_testVectorPath))
        {
            Assert.Fail($"Test vector file not found at: {_testVectorPath}");
        }
    }

    [Test]
    public void TestSp80056COneStepKdf_AllTestVectors()
    {
        var testVectors = Sp80056CTestVectorParser.ParseFile(_testVectorPath);
        
        // Test all vectors (both hash-based and HMAC-based)
        var allVectors = testVectors.ToList();
        
        // Group by hash algorithm
        var vectorsByHash = allVectors.GroupBy(v => v.HashAlgorithm);
        
        foreach (var group in vectorsByHash)
        {
            var hashAlgorithm = group.Key;
            // Testing {group.Count()} vectors for {hashAlgorithm}
            
            foreach (var vector in group)
            {
                TestSingleVector(vector);
            }
        }
        
        // Total vectors tested: {allVectors.Count}
    }

    [Test]
    public void TestSp80056COneStepKdf_SHA1Vectors()
    {
        var testVectors = Sp80056CTestVectorParser.ParseFile(_testVectorPath);
        var sha1Vectors = testVectors.Where(v => v.HashAlgorithm == "SHA-1").ToList();
        
        sha1Vectors.Should().NotBeEmpty("SHA-1 test vectors should exist");
        
        foreach (var vector in sha1Vectors)
        {
            TestSingleVector(vector);
        }
    }

    [Test]
    public void TestSp80056COneStepKdf_SHA256Vectors()
    {
        var testVectors = Sp80056CTestVectorParser.ParseFile(_testVectorPath);
        var sha256Vectors = testVectors.Where(v => v.HashAlgorithm == "SHA-256").ToList();
        
        sha256Vectors.Should().NotBeEmpty("SHA-256 test vectors should exist");
        
        foreach (var vector in sha256Vectors)
        {
            TestSingleVector(vector);
        }
    }

    [Test]
    public void TestSp80056COneStepKdf_VariableLengthOutputs()
    {
        var testVectors = Sp80056CTestVectorParser.ParseFile(_testVectorPath);
        
        // Filter out HMAC-based vectors
        var hashBasedVectors = testVectors.Where(v => !v.HashAlgorithm.StartsWith("HMAC")).ToList();
        
        // Find vectors with the same Z and fixedInfo but different L values
        var variableLengthGroups = hashBasedVectors
            .GroupBy(v => new { Z = BitConverter.ToString(v.Z), FixedInfo = BitConverter.ToString(v.FixedInfo), v.HashAlgorithm })
            .Where(g => g.Count() > 1)
            .ToList();
        
        variableLengthGroups.Should().NotBeEmpty("Should have variable length test cases");
        
        foreach (var group in variableLengthGroups)
        {
            // Test that outputs are prefixes of longer outputs
            var orderedVectors = group.OrderBy(v => v.L).ToList();
            
            for (int i = 1; i < orderedVectors.Count; i++)
            {
                var shorter = orderedVectors[i - 1];
                var longer = orderedVectors[i];
                
                // The shorter output should be a prefix of the longer output
                var longerPrefix = longer.Expected.Take(shorter.Expected.Length).ToArray();
                longerPrefix.Should().Equal(shorter.Expected, 
                    $"Shorter output (L={shorter.L}) should be a prefix of longer output (L={longer.L})");
            }
        }
    }

    private void TestSingleVector(Sp80056CTestVectorParser.TestVector vector)
    {
        byte[] derivedKey;
        
        if (vector.HashAlgorithm.StartsWith("HMAC"))
        {
            // Use HMAC-based KDF for HMAC algorithms
            derivedKey = Sp80056CHmacKdf.DeriveKeyMaterial(
                vector.Z,
                vector.FixedInfo,
                vector.L,
                vector.HashAlgorithm);
        }
        else
        {
            // Use SP 800-56A Concat KDF which is the hash-based one-step KDF in SP 800-56C
            derivedKey = Sp80056AConcatKdf.DeriveKeyMaterial(
                vector.Z, 
                vector.FixedInfo, 
                vector.L, 
                vector.HashAlgorithm);
        }
        
        derivedKey.Should().Equal(vector.Expected, 
            $"KDF output mismatch for {vector.HashAlgorithm}, Z length={vector.Z.Length}, L={vector.L}");
    }

    private static string FindProjectRoot(string startPath)
    {
        var directory = new DirectoryInfo(startPath);
        while (directory != null && !directory.GetFiles("*.sln").Any())
        {
            directory = directory.Parent;
        }
        return directory?.FullName ?? throw new InvalidOperationException("Could not find project root");
    }

    [TestCase("SHA-1", 16)]
    [TestCase("SHA-256", 32)]
    [TestCase("SHA-384", 48)]
    [TestCase("SHA-512", 64)]
    public void TestSp80056COneStepKdf_BasicOperation(string hashAlgorithm, int expectedHashSize)
    {
        // Basic test to ensure the KDF works for each hash algorithm
        var z = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        var fixedInfo = new byte[] { 0x10, 0x20, 0x30, 0x40 };
        var outputLength = 32;
        
        var derivedKey = Sp80056AConcatKdf.DeriveKeyMaterial(z, fixedInfo, outputLength, hashAlgorithm);
        
        derivedKey.Should().NotBeNull();
        derivedKey.Length.Should().Be(outputLength);
        derivedKey.Should().NotBeEquivalentTo(new byte[outputLength], "Derived key should not be all zeros");
    }

    [Test]
    public void TestSp80056COneStepKdf_EmptyFixedInfo()
    {
        // Test vectors with empty fixedInfo
        var testVectors = Sp80056CTestVectorParser.ParseFile(_testVectorPath);
        var emptyFixedInfoVectors = testVectors
            .Where(v => !v.HashAlgorithm.StartsWith("HMAC") && v.FixedInfo.Length == 0)
            .ToList();
        
        emptyFixedInfoVectors.Should().NotBeEmpty("Should have test vectors with empty fixedInfo");
        
        foreach (var vector in emptyFixedInfoVectors)
        {
            TestSingleVector(vector);
        }
    }

    [Test]
    public void TestSp80056COneStepKdf_SmallOutputLengths()
    {
        // Test vectors with small L values (2, 4, 6, 8 bytes)
        var testVectors = Sp80056CTestVectorParser.ParseFile(_testVectorPath);
        var smallOutputVectors = testVectors
            .Where(v => !v.HashAlgorithm.StartsWith("HMAC") && v.L <= 8)
            .ToList();
        
        smallOutputVectors.Should().NotBeEmpty("Should have test vectors with small output lengths");
        
        foreach (var vector in smallOutputVectors)
        {
            TestSingleVector(vector);
        }
    }

    [Test]
    public void TestSp80056COneStepKdf_LargeOutputLengths()
    {
        // Test vectors with large L values (> 32 bytes)
        var testVectors = Sp80056CTestVectorParser.ParseFile(_testVectorPath);
        var largeOutputVectors = testVectors
            .Where(v => !v.HashAlgorithm.StartsWith("HMAC") && v.L > 32)
            .ToList();
        
        largeOutputVectors.Should().NotBeEmpty("Should have test vectors with large output lengths");
        
        foreach (var vector in largeOutputVectors)
        {
            TestSingleVector(vector);
        }
    }

    [Test]
    public void TestSp80056COneStepKdf_SHA512Vectors()
    {
        var testVectors = Sp80056CTestVectorParser.ParseFile(_testVectorPath);
        var sha512Vectors = testVectors.Where(v => v.HashAlgorithm == "SHA-512").ToList();
        
        sha512Vectors.Should().NotBeEmpty("SHA-512 test vectors should exist");
        
        foreach (var vector in sha512Vectors)
        {
            TestSingleVector(vector);
        }
    }

    [Test]
    public void TestSp80056COneStepKdf_HMACVectors()
    {
        // Test HMAC-based KDF with HMAC-SHA256 and HMAC-SHA512 vectors
        var testVectors = Sp80056CTestVectorParser.ParseFile(_testVectorPath);
        var hmacVectors = testVectors.Where(v => v.HashAlgorithm.StartsWith("HMAC")).ToList();
        
        hmacVectors.Should().NotBeEmpty("HMAC test vectors should exist");
        
        foreach (var vector in hmacVectors)
        {
            TestSingleVector(vector);
        }
    }
}