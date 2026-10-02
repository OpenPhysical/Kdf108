using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AwesomeAssertions;
using Kdf108.Domain.Sp80056A;
using Microsoft.Extensions.Logging.Testing;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Test.Sp80056A;

/// <summary>
/// CAVP compliance tests for SP 800-56A key agreement schemes using individual test vectors.
/// Each CAVP test vector becomes a separate, discoverable test case for comprehensive validation.
/// </summary>
[TestFixture]
[Category("CAVP")]
[Explicit]
[Parallelizable(ParallelScope.All)]
public class Sp80056ACavpVectorTests
{
    private static readonly FakeLogger<Sp80056AEcdhKeyAgreement> _ecdhLogger = new();
    /// <summary>
    /// Generates test cases for all SP 800-56A CAVP test vectors.
    /// </summary>
    /// <returns>Enumerable of test case data for each individual CAVP vector.</returns>
    private static IEnumerable<TestCaseData> GetAllCavpVectors()
    {
        var testDirectory = FindTestVectorDirectory();
        if (testDirectory == null)
        {
            yield break;
        }

        // Process all three categories
        var categories = new[]
        {
            ("Test of 800-56A excluding KDF", "ZZOnly"),
            ("No Key Confirmation", "NoKC"),
            ("Key Confirmation", "KC")
        };

        foreach (var (categoryPath, categoryCode) in categories)
        {
            var fullCategoryPath = Path.Combine(testDirectory, categoryPath);
            if (!Directory.Exists(fullCategoryPath)) continue;

            foreach (var schemeDir in Directory.GetDirectories(fullCategoryPath))
            {
                var schemeName = Path.GetFileName(schemeDir);
                var schemeCode = GetSchemeCode(schemeName);

                foreach (var testFile in Directory.GetFiles(schemeDir, "*.fax"))
                {
                    var fileName = Path.GetFileNameWithoutExtension(testFile);
                    var vectors = CavpTestVectorParser.ParseFile(testFile);

                    foreach (var vector in vectors)
                    {
                        yield return new TestCaseData(vector, schemeName, categoryCode)
                            .SetName($"SP80056A_{categoryCode}_{schemeCode}_{fileName}_Vector{vector.Count:D4}");
                    }
                }
            }
        }
    }

    /// <summary>
    /// Tests an individual CAVP test vector for SP 800-56A compliance.
    /// </summary>
    /// <param name="vector">The CAVP test vector to validate.</param>
    /// <param name="schemeName">The key agreement scheme name.</param>
    /// <param name="categoryCode">The test category code (ZZOnly, NoKC, KC).</param>
    [TestCaseSource(nameof(GetAllCavpVectors))]
    public void TestCavpVector(CavpTestVector vector, string schemeName, string categoryCode)
    {
        try
        {
            switch (categoryCode)
            {
                case "ZZOnly":
                    TestZZOnlyVector(vector, schemeName);
                    break;
                case "NoKC":
                    TestNoKeyConfirmationVector(vector, schemeName);
                    break;
                case "KC":
                    TestKeyConfirmationVector(vector, schemeName);
                    break;
                default:
                    Assert.Fail($"Unknown test category: {categoryCode}");
                    break;
            }
        }
        catch (Exception) when (vector.ExpectFail)
        {
            // Expected failure - this is acceptable for CAVP compliance testing
            return;
        }
        catch (Exception ex) when (vector.ExpectPass)
        {
            // Unexpected failure for a test that should pass
            Assert.Fail($"Unexpected failure for {schemeName} vector {vector.Count}: {ex.Message}");
        }
    }

    private static void TestZZOnlyVector(CavpTestVector vector, string schemeName)
    {
        // Test shared secret computation without KDF
        var sharedSecret = ComputeSharedSecretForScheme(vector, schemeName);

        if (vector.ExpectPass)
        {
            sharedSecret.Should().NotBeNull();
            sharedSecret.Should().Equal(vector.Z, $"Shared secret mismatch for {schemeName} vector {vector.Count}");
        }
    }

    private static void TestNoKeyConfirmationVector(CavpTestVector vector, string schemeName)
    {
        // Test shared secret computation + SP 800-56A Concat KDF
        var sharedSecret = ComputeSharedSecretForScheme(vector, schemeName);

        if (vector.OI == null || vector.DKM == null || vector.Hash == null)
        {
            Assert.Fail($"Missing required KDF parameters for {schemeName} vector {vector.Count}");
            return;
        }

        var derivedKey = Sp80056AConcatKdf.DeriveKeyMaterial(sharedSecret, vector.OI, vector.DKM.Length, vector.Hash);

        if (vector.ExpectPass)
        {
            derivedKey.Should().Equal(vector.DKM, $"Derived key mismatch for {schemeName} vector {vector.Count}");
        }
    }

    private static void TestKeyConfirmationVector(CavpTestVector vector, string schemeName)
    {
        // Test shared secret + KDF + MAC verification
        var sharedSecret = ComputeSharedSecretForScheme(vector, schemeName);

        if (vector.OI == null || vector.DKM == null || vector.Hash == null)
        {
            Assert.Fail($"Missing required KDF parameters for {schemeName} vector {vector.Count}");
            return;
        }

        var derivedKey = Sp80056AConcatKdf.DeriveKeyMaterial(sharedSecret, vector.OI, vector.DKM.Length, vector.Hash);

        if (vector.ExpectPass)
        {
            derivedKey.Should().Equal(vector.DKM, $"Derived key mismatch for {schemeName} vector {vector.Count}");

            // TODO: Add MAC verification when CAVSTag is present in vector
            if (vector.CAVSTag != null)
            {
                // Verify MAC tag computation using vector.CAVSTag
            }
        }
    }

    /// <summary>
    /// Computes the shared secret for a specific key agreement scheme based on the test vector data.
    /// </summary>
    /// <param name="vector">The CAVP test vector containing key material and parameters</param>
    /// <param name="schemeName">The name of the key agreement scheme to test</param>
    /// <returns>The computed shared secret as a byte array</returns>
    private static byte[] ComputeSharedSecretForScheme(CavpTestVector vector, string schemeName)
    {
        var actualCurve = vector.Curve;
        if (string.IsNullOrEmpty(actualCurve))
        {
            throw new InvalidOperationException($"No curve specified for vector {vector.Count}");
        }

        var ecdhInstance = CreateEcdhForCurve(actualCurve);

        switch (schemeName)
        {
            case "ECC Static Unified Scheme":
            case "ECC StaticUnified Scheme":
                if (vector.DsIUT == null || vector.QsCAVSx == null || vector.QsCAVSy == null)
                    throw new InvalidOperationException($"Missing required static keys for {schemeName} vector {vector.Count}");
                var staticCavsPublicKey = CreateUncompressedPublicKeyForCurve(vector.QsCAVSx, vector.QsCAVSy, actualCurve);
                return ecdhInstance!.PerformKeyAgreement(vector.DsIUT, staticCavsPublicKey);

            case "ECC One Pass DH Scheme":
                if (vector.DeCAVS != null && vector.QsIUTx != null && vector.QsIUTy != null)
                {
                    var onePassIutPublicKey = CreateUncompressedPublicKeyForCurve(vector.QsIUTx, vector.QsIUTy, actualCurve);
                    return ecdhInstance!.PerformKeyAgreement(vector.DeCAVS, onePassIutPublicKey);
                }
                else if (vector.DeIUT != null && vector.QsCAVSx != null && vector.QsCAVSy != null)
                {
                    var onePassCavsPublicKey = CreateUncompressedPublicKeyForCurve(vector.QsCAVSx, vector.QsCAVSy, actualCurve);
                    return ecdhInstance!.PerformKeyAgreement(vector.DeIUT, onePassCavsPublicKey);
                }
                else if (vector.DsIUT != null && vector.QeCAVSx != null && vector.QeCAVSy != null)
                {
                    var onePassCavsPublicKey = CreateUncompressedPublicKeyForCurve(vector.QeCAVSx, vector.QeCAVSy, actualCurve);
                    return ecdhInstance!.PerformKeyAgreement(vector.DsIUT, onePassCavsPublicKey);
                }
                else
                {
                    throw new InvalidOperationException($"Missing required keys for {schemeName} vector {vector.Count}");
                }

            case "ECC Full Unified Scheme":
            case "ECC FullUnified Scheme":
                if (vector.DeIUT == null || vector.QeCAVSx == null || vector.QeCAVSy == null ||
                    vector.DsIUT == null || vector.QsCAVSx == null || vector.QsCAVSy == null)
                    throw new InvalidOperationException($"Missing required keys for {schemeName} vector {vector.Count}");

                var fullUnifiedEphemeralCavsKey = CreateUncompressedPublicKeyForCurve(vector.QeCAVSx, vector.QeCAVSy, actualCurve);
                var fullUnifiedStaticCavsKey = CreateUncompressedPublicKeyForCurve(vector.QsCAVSx, vector.QsCAVSy, actualCurve);

                var ze = ecdhInstance!.PerformKeyAgreement(vector.DeIUT, fullUnifiedEphemeralCavsKey);
                var zs = ecdhInstance.PerformKeyAgreement(vector.DsIUT, fullUnifiedStaticCavsKey);

                var result = new byte[ze.Length + zs.Length];
                Buffer.BlockCopy(ze, 0, result, 0, ze.Length);
                Buffer.BlockCopy(zs, 0, result, ze.Length, zs.Length);
                return result;

            case "ECC One Pass Unified Scheme":
            case "ECC OnePass Unified Scheme":
                if (vector.DeIUT != null && vector.DsIUT != null &&
                    vector.QsCAVSx != null && vector.QsCAVSy != null)
                {
                    var onePassUnifiedStaticCavsKey = CreateUncompressedPublicKeyForCurve(vector.QsCAVSx, vector.QsCAVSy, actualCurve);

                    var ze1 = ecdhInstance!.PerformKeyAgreement(vector.DeIUT, onePassUnifiedStaticCavsKey);
                    var zs1 = ecdhInstance.PerformKeyAgreement(vector.DsIUT, onePassUnifiedStaticCavsKey);

                    var result1 = new byte[ze1.Length + zs1.Length];
                    Buffer.BlockCopy(ze1, 0, result1, 0, ze1.Length);
                    Buffer.BlockCopy(zs1, 0, result1, ze1.Length, zs1.Length);
                    return result1;
                }
                else if (vector.DeCAVS != null && vector.DsCAVS != null &&
                         vector.QsIUTx != null && vector.QsIUTy != null)
                {
                    var onePassUnifiedStaticIutKey = CreateUncompressedPublicKeyForCurve(vector.QsIUTx, vector.QsIUTy, actualCurve);

                    var ze2 = ecdhInstance!.PerformKeyAgreement(vector.DeCAVS, onePassUnifiedStaticIutKey);
                    var zs2 = ecdhInstance.PerformKeyAgreement(vector.DsCAVS, onePassUnifiedStaticIutKey);

                    var result2 = new byte[ze2.Length + zs2.Length];
                    Buffer.BlockCopy(ze2, 0, result2, 0, ze2.Length);
                    Buffer.BlockCopy(zs2, 0, result2, ze2.Length, zs2.Length);
                    return result2;
                }
                else
                {
                    throw new InvalidOperationException($"Missing required keys for {schemeName} vector {vector.Count}");
                }

            case "ECC Full MQV Scheme":
                if (vector.DeIUT == null || vector.DsIUT == null ||
                    vector.QeCAVSx == null || vector.QeCAVSy == null ||
                    vector.QsCAVSx == null || vector.QsCAVSy == null)
                    throw new InvalidOperationException($"Missing required keys for {schemeName} vector {vector.Count}");

                return PerformMqvAgreement(
                    vector.DeIUT, vector.DsIUT,
                    vector.QeCAVSx, vector.QeCAVSy,
                    vector.QsCAVSx, vector.QsCAVSy,
                    actualCurve!);

            case "ECC One Pass MQV Scheme":
            case "ECC OnePass MQV Scheme":
                if (vector.DsIUT != null && vector.QeCAVSx != null && vector.QeCAVSy != null &&
                    vector.QsCAVSx != null && vector.QsCAVSy != null)
                {
                    return PerformMqvAgreement(
                        vector.DsIUT, vector.DsIUT,
                        vector.QeCAVSx, vector.QeCAVSy,
                        vector.QsCAVSx, vector.QsCAVSy,
                        actualCurve!);
                }
                else if (vector.DeCAVS != null && vector.DsCAVS != null &&
                         vector.QsIUTx != null && vector.QsIUTy != null)
                {
                    return PerformMqvAgreement(
                        vector.DeCAVS, vector.DsCAVS,
                        vector.QsIUTx, vector.QsIUTy,
                        vector.QsIUTx, vector.QsIUTy,
                        actualCurve!);
                }
                else if (vector.DeIUT != null && vector.DsIUT != null && vector.DsCAVS != null &&
                         vector.QeIUTx != null && vector.QeIUTy != null &&
                         vector.QsIUTx != null && vector.QsIUTy != null &&
                         vector.QsCAVSx != null && vector.QsCAVSy != null)
                {
                    return PerformMqvAgreement(
                        vector.DsCAVS, vector.DsCAVS,
                        vector.QeIUTx, vector.QeIUTy,
                        vector.QsIUTx, vector.QsIUTy,
                        actualCurve!);
                }
                else
                {
                    throw new InvalidOperationException($"Missing required keys for {schemeName} vector {vector.Count}");
                }

            case "ECC Ephemeral Unified Scheme":
                if (vector.DeIUT == null || vector.QeCAVSx == null || vector.QeCAVSy == null)
                    throw new InvalidOperationException($"Missing required ephemeral keys for {schemeName} vector {vector.Count}");
                var ephemeralCavsPublicKey = CreateUncompressedPublicKeyForCurve(vector.QeCAVSx, vector.QeCAVSy, actualCurve);
                return ecdhInstance!.PerformKeyAgreement(vector.DeIUT, ephemeralCavsPublicKey);

            default:
                throw new NotImplementedException($"Shared secret computation not implemented for {schemeName}");
        }
    }

    private static string GetSchemeCode(string schemeName)
    {
        return schemeName switch
        {
            "ECC Ephemeral Unified Scheme" => "EphemeralUnified",
            "ECC Static Unified Scheme" => "StaticUnified",
            "ECC StaticUnified Scheme" => "StaticUnified",
            "ECC Full Unified Scheme" => "FullUnified",
            "ECC FullUnified Scheme" => "FullUnified",
            "ECC One Pass Unified Scheme" => "OnePassUnified",
            "ECC OnePass Unified Scheme" => "OnePassUnified",
            "ECC One Pass DH Scheme" => "OnePassDH",
            "ECC Full MQV Scheme" => "FullMQV",
            "ECC One Pass MQV Scheme" => "OnePassMQV",
            "ECC OnePass MQV Scheme" => "OnePassMQV",
            _ => schemeName.Replace(" ", "").Replace("ECC", "")
        };
    }

    private static string? FindTestVectorDirectory()
    {
        // Find the project root by looking for the .csproj file
        var currentDir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (currentDir != null && !currentDir.GetFiles("*.csproj").Any())
        {
            currentDir = currentDir.Parent;
        }

        if (currentDir == null)
        {
            return null;
        }

        var testVectorPath = Path.Combine(currentDir.FullName, "res", "vectors", "SP800-56A", "KASTestVectorsECC2016");
        return Directory.Exists(testVectorPath) ? testVectorPath : null;
    }

    /// <summary>
    /// Creates an ECDH key agreement instance for the specified curve.
    /// </summary>
    /// <param name="curveName">The name of the elliptic curve (e.g., "P-256", "B-571")</param>
    /// <returns>An ECDH instance configured for the curve, or null if unsupported</returns>
    private static Sp80056AEcdhKeyAgreement CreateEcdhForCurve(string? curveName)
    {
        if (string.IsNullOrEmpty(curveName))
        {
            throw new ArgumentException("Curve name cannot be null or empty", nameof(curveName));
        }

        return curveName switch
        {
            "P-224" => Sp80056AEcdhKeyAgreement.CreateP224(_ecdhLogger),
            "P-256" => Sp80056AEcdhKeyAgreement.CreateP256(_ecdhLogger),
            "P-384" => Sp80056AEcdhKeyAgreement.CreateP384(_ecdhLogger),
            "P-521" => Sp80056AEcdhKeyAgreement.CreateP521(_ecdhLogger),
            "B-233" => Sp80056AEcdhKeyAgreement.CreateB233(_ecdhLogger),
            "K-233" => Sp80056AEcdhKeyAgreement.CreateK233(_ecdhLogger),
            "K-283" => Sp80056AEcdhKeyAgreement.CreateK283(_ecdhLogger),
            "B-409" => Sp80056AEcdhKeyAgreement.CreateB409(_ecdhLogger),
            "B-571" => Sp80056AEcdhKeyAgreement.CreateB571(_ecdhLogger),
            "K-571" => Sp80056AEcdhKeyAgreement.CreateK571(_ecdhLogger),
            _ => throw new NotSupportedException($"Curve {curveName} is not supported")
        };
    }

    /// <summary>
    /// Creates an uncompressed public key with proper coordinate padding based on the curve.
    /// </summary>
    /// <param name="x">The X coordinate bytes</param>
    /// <param name="y">The Y coordinate bytes</param>
    /// <param name="curveName">The name of the elliptic curve</param>
    /// <returns>Uncompressed public key in the format 0x04||x||y</returns>
    private static byte[] CreateUncompressedPublicKeyForCurve(byte[] x, byte[] y, string? curveName)
    {
        int expectedLength = curveName switch
        {
            "P-224" => 28,
            "P-256" => 32,
            "P-384" => 48,
            "P-521" => 66,
            "B-233" => 30,
            "K-233" => 30,
            "B-283" => 36,
            "K-283" => 36,
            "B-409" => 52,
            "K-409" => 52,
            "B-571" => 72,
            "K-571" => 72,
            _ => 0
        };

        if (expectedLength == 0)
        {
            return CreateUncompressedPublicKey(x, y);
        }

        byte[] paddedX = PadCoordinate(x, expectedLength);
        byte[] paddedY = PadCoordinate(y, expectedLength);

        var uncompressed = new byte[1 + paddedX.Length + paddedY.Length];
        uncompressed[0] = 0x04;
        Array.Copy(paddedX, 0, uncompressed, 1, paddedX.Length);
        Array.Copy(paddedY, 0, uncompressed, 1 + paddedX.Length, paddedY.Length);
        return uncompressed;
    }

    /// <summary>
    /// Creates an uncompressed public key without curve-specific padding.
    /// </summary>
    /// <param name="x">The X coordinate bytes</param>
    /// <param name="y">The Y coordinate bytes</param>
    /// <returns>Uncompressed public key in the format 0x04||x||y</returns>
    private static byte[] CreateUncompressedPublicKey(byte[] x, byte[] y)
    {
        var uncompressed = new byte[1 + x.Length + y.Length];
        uncompressed[0] = 0x04;
        Array.Copy(x, 0, uncompressed, 1, x.Length);
        Array.Copy(y, 0, uncompressed, 1 + x.Length, y.Length);
        return uncompressed;
    }

    /// <summary>
    /// Pads or trims a coordinate to the expected length for the curve.
    /// </summary>
    /// <param name="coordinate">The coordinate bytes</param>
    /// <param name="expectedLength">The expected length in bytes</param>
    /// <returns>The coordinate padded or trimmed to the expected length</returns>
    private static byte[] PadCoordinate(byte[] coordinate, int expectedLength)
    {
        if (coordinate.Length == expectedLength)
        {
            return coordinate;
        }

        if (coordinate.Length > expectedLength)
        {
            int leadingZeros = 0;
            for (int i = 0; i < coordinate.Length - expectedLength; i++)
            {
                if (coordinate[i] == 0)
                {
                    leadingZeros++;
                }
                else
                {
                    break;
                }
            }

            if (leadingZeros >= coordinate.Length - expectedLength)
            {
                byte[] trimmed = new byte[expectedLength];
                Array.Copy(coordinate, coordinate.Length - expectedLength, trimmed, 0, expectedLength);
                return trimmed;
            }

            throw new ArgumentException($"Coordinate length {coordinate.Length} exceeds expected length {expectedLength} and cannot be trimmed");
        }

        byte[] padded = new byte[expectedLength];
        Array.Copy(coordinate, 0, padded, expectedLength - coordinate.Length, coordinate.Length);
        return padded;
    }

    /// <summary>
    /// Performs MQV key agreement using BouncyCastle's MQV implementation.
    /// </summary>
    private static byte[] PerformMqvAgreement(
        byte[] ephemeralPrivateKey,
        byte[] staticPrivateKey,
        byte[] otherEphemeralPublicKeyX,
        byte[] otherEphemeralPublicKeyY,
        byte[] otherStaticPublicKeyX,
        byte[] otherStaticPublicKeyY,
        string curveName)
    {
        var curveParams = GetCurveParameters(curveName);
        if (curveParams == null)
        {
            throw new InvalidOperationException($"Unsupported curve: {curveName}");
        }

        var ephemeralPrivKey = new ECPrivateKeyParameters(new Org.BouncyCastle.Math.BigInteger(1, ephemeralPrivateKey), curveParams);
        var staticPrivKey = new ECPrivateKeyParameters(new Org.BouncyCastle.Math.BigInteger(1, staticPrivateKey), curveParams);

        var otherEphemeralPubKey = CreateECPublicKeyParameters(otherEphemeralPublicKeyX, otherEphemeralPublicKeyY, curveParams);
        var otherStaticPubKey = CreateECPublicKeyParameters(otherStaticPublicKeyX, otherStaticPublicKeyY, curveParams);

        var mqvPrivateParams = new MqvPrivateParameters(staticPrivKey, ephemeralPrivKey);
        var mqvPublicParams = new MqvPublicParameters(otherStaticPubKey, otherEphemeralPubKey);

        var mqvAgreement = new ECMqvBasicAgreement();
        mqvAgreement.Init(mqvPrivateParams);

        var sharedSecret = mqvAgreement.CalculateAgreement(mqvPublicParams);

        var expectedLength = (curveParams.Curve.FieldSize + 7) / 8;
        return ConvertBigIntegerToBytes(sharedSecret, expectedLength);
    }

    /// <summary>
    /// Gets the BouncyCastle curve parameters for a named curve.
    /// </summary>
    private static ECDomainParameters? GetCurveParameters(string curveName)
    {
        var curveName2 = curveName switch
        {
            "P-224" => "secp224r1",
            "P-256" => "secp256r1",
            "P-384" => "secp384r1",
            "P-521" => "secp521r1",
            "B-233" => "sect233r1",
            "K-233" => "sect233k1",
            "K-283" => "sect283k1",
            "B-409" => "sect409r1",
            "B-571" => "sect571r1",
            _ => null
        };

        if (curveName2 == null)
            return null;

        var x9params = ECNamedCurveTable.GetByName(curveName2);
        if (x9params == null)
            return null;

        return new ECDomainParameters(x9params.Curve, x9params.G, x9params.N, x9params.H);
    }

    /// <summary>
    /// Creates BouncyCastle EC public key parameters from coordinate bytes.
    /// </summary>
    private static ECPublicKeyParameters CreateECPublicKeyParameters(byte[] x, byte[] y, ECDomainParameters domainParams)
    {
        var curve = domainParams.Curve;
        var xElement = new Org.BouncyCastle.Math.BigInteger(1, x);
        var yElement = new Org.BouncyCastle.Math.BigInteger(1, y);

        var point = curve.CreatePoint(xElement, yElement);
        return new ECPublicKeyParameters(point, domainParams);
    }

    /// <summary>
    /// Converts a BouncyCastle BigInteger to a byte array with proper padding.
    /// </summary>
    private static byte[] ConvertBigIntegerToBytes(Org.BouncyCastle.Math.BigInteger value, int expectedLength)
    {
        var bytes = value.ToByteArrayUnsigned();

        if (bytes.Length == expectedLength)
        {
            return bytes;
        }

        if (bytes.Length > expectedLength)
        {
            var trimmed = new byte[expectedLength];
            Array.Copy(bytes, bytes.Length - expectedLength, trimmed, 0, expectedLength);
            return trimmed;
        }

        var padded = new byte[expectedLength];
        Array.Copy(bytes, 0, padded, expectedLength - bytes.Length, bytes.Length);
        return padded;
    }
}
