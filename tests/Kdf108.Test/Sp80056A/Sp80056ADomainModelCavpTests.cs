// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AwesomeAssertions;
using Kdf108.Domain.Sp80056A;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Interfaces.Kdf;
using Kdf108.Exceptions;
using Kdf108.Test.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace Kdf108.Test.Sp80056A;

/// <summary>
/// CAVP compliance tests using domain models that validate keys at construction.
/// </summary>
[TestFixture]
[Category("CAVP")]
[Parallelizable(ParallelScope.All)]
public class Sp80056ADomainModelCavpTests
{
    private IKdfEngine _kdfEngine;
    private FakeLogger<EcPrivateKey> _privateKeyLogger;
    private FakeLogger<EcPublicKey> _publicKeyLogger;
    private FakeLogger<EcKeyPair> _keyPairLogger;
    
    [SetUp]
    public void Setup()
    {
        _privateKeyLogger = new FakeLogger<EcPrivateKey>();
        _publicKeyLogger = new FakeLogger<EcPublicKey>();
        _keyPairLogger = new FakeLogger<EcKeyPair>();
        _kdfEngine = KdfEngine.CreateDefault();
    }

    [Test]
    [Category("KeyAgreement")]
    [Category("ZZOnly")]
    public void EphemeralUnified_ZZOnly_InitiatorTests()
    {
        var testVectorPath = GetTestVectorPath(
            "Test of 800-56A excluding KDF", "ECC Ephemeral Unified Scheme",
            "KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_init.fax");

        if (!File.Exists(testVectorPath))
        {
            Assert.Ignore($"Test vector file not found: {testVectorPath}");
            return;
        }

        var testVectors = CavpTestVectorParser.ParseFile(testVectorPath);

        foreach (var vector in testVectors)
        {
            TestEphemeralUnifiedZZOnly(vector);
        }
    }

    private void TestEphemeralUnifiedZZOnly(CavpTestVector vector)
    {
        if (!vector.Count.HasValue) return;

        // Curve must be set in test vector
        if (string.IsNullOrEmpty(vector.Curve))
        {
            Assert.Fail($"Test vector {vector.Count} has no curve specified");
        }
        string curveName = vector.Curve!;

        try
        {
            // Model reality: if CAVP gives us a keypair, create a KeyPair object
            // This is where validation happens - at construction
            EcKeyPair? iutEphemeralKeyPair = null;
            Exception? keyPairException = null;
            
            // Try to create keypair with compliance handling if needed
            if (!CavpCompliance.TryCreateKeyPairWithCompliance(
                vector.DeIUT, vector.QeIUTx, vector.QeIUTy, 
                curveName, vector.ErrorCode,
                out iutEphemeralKeyPair, out keyPairException))
            {
                // If we have an exception and the test should fail, check it now
                if (keyPairException != null && vector.Result == "F")
                {
                    ValidateExpectedException(keyPairException, vector.ErrorCode);
                    return; // Test passed - got expected exception
                }
                
                // Otherwise, try normal creation if we don't have a keypair yet
                if (iutEphemeralKeyPair == null && vector.DeIUT != null && 
                    vector.QeIUTx != null && vector.QeIUTy != null)
                {
                    var privateKey = new EcPrivateKey(vector.DeIUT, curveName, _privateKeyLogger);
                    var publicKeyBytes = CreateUncompressedPublicKey(vector.QeIUTx, vector.QeIUTy);
                    var publicKey = new EcPublicKey(publicKeyBytes, curveName, _publicKeyLogger);
                    
                    // This will throw KeyMismatchException if keys don't match
                    iutEphemeralKeyPair = EcKeyPair.Create(privateKey, publicKey, _keyPairLogger);
                }
            }

            // Create CAVS public key
            if (vector.QeCAVSx == null || vector.QeCAVSy == null)
            {
                Assert.Fail($"Missing CAVS ephemeral public key for vector {vector.Count}");
                return;
            }
            var cavsPublicKeyBytes = CreateUncompressedPublicKey(vector.QeCAVSx, vector.QeCAVSy);
            var cavsPublicKey = new EcPublicKey(cavsPublicKeyBytes, curveName, _publicKeyLogger);

            // Compute shared secret using the clean API
            SharedSecret sharedSecret;
            if (iutEphemeralKeyPair != null)
            {
                // We have a validated keypair
                sharedSecret = EcdhKeyAgreement.ComputeEphemeralUnified(
                    iutEphemeralKeyPair, cavsPublicKey);
            }
            else if (vector.DeIUT != null)
            {
                // We only have a private key
                var privateKey = new EcPrivateKey(vector.DeIUT, curveName, _privateKeyLogger);
                sharedSecret = EcdhKeyAgreement.ComputeSharedSecret(
                    privateKey, cavsPublicKey);
            }
            else
            {
                Assert.Fail($"No IUT ephemeral key available for vector {vector.Count}");
                return;
            }

            // Verify result
            if (vector.Result == "P")
            {
                // Should pass - verify shared secret matches
                sharedSecret.ToArray().Should().BeEquivalentTo(vector.Z);
            }
            else
            {
                // Should have failed but didn't
                Assert.Fail($"Vector {vector.Count} should have failed but succeeded");
            }
        }
        catch (Exception ex) when (vector.Result == "F")
        {
            // Expected failure - check the type of exception based on error code
            ValidateExpectedException(ex, vector.ErrorCode);
        }
        catch (Exception ex) when (AttachLogs(ex))
        {
            // Unexpected failure - logs will be attached
            throw;
        }
    }

    [Test]
    [Category("KeyAgreement")]
    [Category("ZZOnly")]
    public void StaticUnified_ZZOnly_Tests()
    {
        var testVectorPath = GetTestVectorPath(
            "Test of 800-56A excluding KDF", "ECC StaticUnified Scheme",
            "KASValidityTest_ECCStaticUnified_NOKC_ZZOnly_init.fax");

        if (!File.Exists(testVectorPath))
        {
            Assert.Ignore($"Test vector file not found: {testVectorPath}");
            return;
        }

        var testVectors = CavpTestVectorParser.ParseFile(testVectorPath);

        foreach (var vector in testVectors)
        {
            TestStaticUnifiedZZOnly(vector);
        }
    }

    private void TestStaticUnifiedZZOnly(CavpTestVector vector)
    {
        if (!vector.Count.HasValue) return;

        if (string.IsNullOrEmpty(vector.Curve))
        {
            Assert.Fail($"Test vector {vector.Count} has no curve specified");
        }
        string curveName = vector.Curve!;

        try
        {
            // Model reality: if we have both IUT static keys, create a KeyPair
            EcKeyPair? iutStaticKeyPair = null;
            Exception? keyPairException = null;
            
            // Try to create keypair with compliance handling if needed
            if (!CavpCompliance.TryCreateKeyPairWithCompliance(
                vector.DsIUT, vector.QsIUTx, vector.QsIUTy, 
                curveName, vector.ErrorCode,
                out iutStaticKeyPair, out keyPairException))
            {
                // If we have an exception and the test should fail, check it now
                if (keyPairException != null && vector.Result == "F")
                {
                    ValidateExpectedException(keyPairException, vector.ErrorCode);
                    return; // Test passed - got expected exception
                }
                
                // Otherwise, try normal creation
                if (iutStaticKeyPair == null && vector.DsIUT != null && 
                    vector.QsIUTx != null && vector.QsIUTy != null)
                {
                    var privateKey = new EcPrivateKey(vector.DsIUT, curveName, _privateKeyLogger);
                    var publicKeyBytes = CreateUncompressedPublicKey(vector.QsIUTx, vector.QsIUTy);
                    var publicKey = new EcPublicKey(publicKeyBytes, curveName, _publicKeyLogger);
                    
                    // KeyMismatchException thrown here if they don't match
                    iutStaticKeyPair = EcKeyPair.Create(privateKey, publicKey, _keyPairLogger);
                }
            }

            // Create CAVS public key
            if (vector.QsCAVSx == null || vector.QsCAVSy == null)
            {
                Assert.Fail($"Missing CAVS static public key for vector {vector.Count}");
                return;
            }
            var cavsPublicKeyBytes = CreateUncompressedPublicKey(vector.QsCAVSx, vector.QsCAVSy);
            var cavsPublicKey = new EcPublicKey(cavsPublicKeyBytes, curveName, _publicKeyLogger);

            // Compute shared secret
            SharedSecret sharedSecret;
            if (iutStaticKeyPair != null)
            {
                sharedSecret = EcdhKeyAgreement.ComputeStaticUnified(
                    iutStaticKeyPair, cavsPublicKey);
            }
            else if (vector.DsIUT != null)
            {
                var privateKey = new EcPrivateKey(vector.DsIUT, curveName, _privateKeyLogger);
                sharedSecret = EcdhKeyAgreement.ComputeSharedSecret(
                    privateKey, cavsPublicKey);
            }
            else
            {
                Assert.Fail($"No IUT static key available for vector {vector.Count}");
                return;
            }

            // Verify result
            if (vector.Result == "P")
            {
                sharedSecret.ToArray().Should().BeEquivalentTo(vector.Z);
            }
            else
            {
                Assert.Fail($"Vector {vector.Count} should have failed but succeeded");
            }
        }
        catch (Exception ex) when (vector.Result == "F")
        {
            ValidateExpectedException(ex, vector.ErrorCode);
        }
        catch (Exception ex) when (AttachLogs(ex))
        {
            throw;
        }
    }

    [Test]
    [Category("KeyAgreement")]
    [Category("ZZOnly")]
    public void FullUnified_ZZOnly_Tests()
    {
        var testVectorPath = GetTestVectorPath(
            "Test of 800-56A excluding KDF", "ECC FullUnified Scheme",
            "KASValidityTest_ECCFullUnified_NOKC_ZZOnly_init.fax");

        if (!File.Exists(testVectorPath))
        {
            Assert.Ignore($"Test vector file not found: {testVectorPath}");
            return;
        }

        var testVectors = CavpTestVectorParser.ParseFile(testVectorPath);

        foreach (var vector in testVectors)
        {
            TestFullUnifiedZZOnly(vector);
        }
    }

    private void TestFullUnifiedZZOnly(CavpTestVector vector)
    {
        if (!vector.Count.HasValue) return;

        if (string.IsNullOrEmpty(vector.Curve))
        {
            Assert.Fail($"Test vector {vector.Count} has no curve specified");
        }
        string curveName = vector.Curve!;

        try
        {
            // Full Unified needs both static and ephemeral keypairs
            EcKeyPair? iutStaticKeyPair = null;
            EcKeyPair? iutEphemeralKeyPair = null;

            // Create IUT static keypair if we have both keys
            if (vector.DsIUT != null && vector.QsIUTx != null && vector.QsIUTy != null)
            {
                var privateKey = new EcPrivateKey(vector.DsIUT, curveName, _privateKeyLogger);
                var publicKeyBytes = CreateUncompressedPublicKey(vector.QsIUTx, vector.QsIUTy);
                var publicKey = new EcPublicKey(publicKeyBytes, curveName, _publicKeyLogger);
                iutStaticKeyPair = EcKeyPair.Create(privateKey, publicKey, _keyPairLogger);
            }

            // Create IUT ephemeral keypair if we have both keys
            if (vector.DeIUT != null && vector.QeIUTx != null && vector.QeIUTy != null)
            {
                var privateKey = new EcPrivateKey(vector.DeIUT, curveName, _privateKeyLogger);
                var publicKeyBytes = CreateUncompressedPublicKey(vector.QeIUTx, vector.QeIUTy);
                var publicKey = new EcPublicKey(publicKeyBytes, curveName, _publicKeyLogger);
                iutEphemeralKeyPair = EcKeyPair.Create(privateKey, publicKey, _keyPairLogger);
            }

            // Create CAVS public keys
            if (vector.QsCAVSx == null || vector.QsCAVSy == null || 
                vector.QeCAVSx == null || vector.QeCAVSy == null)
            {
                Assert.Fail($"Missing CAVS public keys for vector {vector.Count}");
                return;
            }
            var cavsStaticPublicKey = new EcPublicKey(
                CreateUncompressedPublicKey(vector.QsCAVSx, vector.QsCAVSy), 
                curveName, _publicKeyLogger);
            var cavsEphemeralPublicKey = new EcPublicKey(
                CreateUncompressedPublicKey(vector.QeCAVSx, vector.QeCAVSy), 
                curveName, _publicKeyLogger);

            // For Full Unified, we need both keypairs
            if (iutStaticKeyPair == null)
            {
                iutStaticKeyPair = EcKeyPair.GenerateFrom(
                    new EcPrivateKey(vector.DsIUT!, curveName, _privateKeyLogger), 
                    _keyPairLogger);
            }
            if (iutEphemeralKeyPair == null)
            {
                iutEphemeralKeyPair = EcKeyPair.GenerateFrom(
                    new EcPrivateKey(vector.DeIUT!, curveName, _privateKeyLogger), 
                    _keyPairLogger);
            }

            // Compute shared secret
            var sharedSecret = EcdhKeyAgreement.ComputeFullUnified(
                iutStaticKeyPair, iutEphemeralKeyPair,
                cavsStaticPublicKey, cavsEphemeralPublicKey);

            // Verify result
            if (vector.Result == "P")
            {
                sharedSecret.ToArray().Should().BeEquivalentTo(vector.Z);
            }
            else
            {
                Assert.Fail($"Vector {vector.Count} should have failed but succeeded");
            }
        }
        catch (Exception ex) when (vector.Result == "F")
        {
            ValidateExpectedException(ex, vector.ErrorCode);
        }
        catch (Exception ex) when (AttachLogs(ex))
        {
            throw;
        }
    }

    /// <summary>
    /// Validates that the correct exception was thrown based on CAVP error code.
    /// </summary>
    private void ValidateExpectedException(Exception ex, string? errorCode)
    {
        switch (errorCode)
        {
            case "2": // Static public key Y fails validation
            case "3": // Ephemeral public key X fails validation
                // Any of these public key exceptions are acceptable
                ex.Should().Match<Exception>(e => 
                    e is InvalidPublicKeyException ||
                    e is InvalidPublicKeyXCoordinateException ||
                    e is InvalidPublicKeyYCoordinateException ||
                    e is PublicKeyNotOnCurveException);
                break;
                
            case "7": // Private key doesn't match public key
                ex.Should().BeOfType<KeyMismatchException>();
                break;
                
            default:
                // Any cryptographic exception is acceptable for other error codes
                ex.Should().BeAssignableTo<CryptographicException>();
                break;
        }
    }

    /// <summary>
    /// Creates an uncompressed public key from X and Y coordinates.
    /// </summary>
    private static byte[] CreateUncompressedPublicKey(byte[] x, byte[] y)
    {
        var result = new byte[1 + x.Length + y.Length];
        result[0] = 0x04; // Uncompressed format
        Array.Copy(x, 0, result, 1, x.Length);
        Array.Copy(y, 0, result, 1 + x.Length, y.Length);
        return result;
    }

    /// <summary>
    /// Gets the test vector file path.
    /// </summary>
    private static string GetTestVectorPath(string category, string scheme, string fileName)
    {
        var baseDir = TestContext.CurrentContext.TestDirectory;
        return Path.Combine(baseDir, "res", "vectors", "SP800-56A", category, scheme, fileName);
    }

    /// <summary>
    /// Attaches logs to exceptions for debugging.
    /// </summary>
    private bool AttachLogs(Exception ex)
    {
        var logs = new List<string>();
        
        if (_privateKeyLogger.Collector.Count > 0)
        {
            logs.Add("=== ECDH Logs ===");
            logs.AddRange(_privateKeyLogger.GetFormattedLogs().Split(Environment.NewLine));
        }
        
        if (_keyPairLogger.Collector.Count > 0)
        {
            logs.Add("=== KeyPair Logs ===");
            logs.AddRange(_keyPairLogger.GetFormattedLogs().Split(Environment.NewLine));
        }
        
        if (logs.Any())
        {
            throw new ExceptionWithLogContext($"Test failed: {ex.Message}", ex)
            {
                LogContext = string.Join(Environment.NewLine, logs)
            };
        }
        
        return false; // Never actually returns true, used in exception filter
    }
}
