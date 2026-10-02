using System;
using AwesomeAssertions;
using Kdf108.Domain.Sp80056A;
using Kdf108.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Kdf108.Test.Sp80056A;

[TestFixture]
[Category("Unit")]
public class Sp80056AEcdhKeyAgreementTests
{
    private FakeLogger<Sp80056AEcdhKeyAgreement> _fakeLogger;
    private SecureRandom _random;

    [SetUp]
    public void Setup()
    {
        _fakeLogger = new FakeLogger<Sp80056AEcdhKeyAgreement>();
        _random = new SecureRandom();
    }

    [TestCase("P-256")]
    [TestCase("P-384")]
    [TestCase("P-521")]
    public void PerformKeyAgreement_ValidKeys_GeneratesCorrectSharedSecret(string curveName)
    {
        // Arrange
        var logger = _fakeLogger;
        var ecdh = CreateEcdhForCurve(curveName, logger);

        var (alicePrivate, alicePublic) = GenerateKeyPair(curveName);
        var (bobPrivate, bobPublic) = GenerateKeyPair(curveName);

        // Act
        var sharedSecret1 = ecdh.PerformKeyAgreement(
            alicePrivate.D.ToByteArrayUnsigned(),
            bobPublic.Q.GetEncoded(false));

        var sharedSecret2 = ecdh.PerformKeyAgreement(
            bobPrivate.D.ToByteArrayUnsigned(),
            alicePublic.Q.GetEncoded(false));

        // Assert
        sharedSecret1.Should().NotBeNull();
        sharedSecret2.Should().NotBeNull();
        sharedSecret1.Should().Equal(sharedSecret2);
        // P-521 produces 66 bytes due to padding
        var expectedSize = curveName == "P-521" ? 66 : ecdh.SharedSecretSize / 8;
        sharedSecret1.Length.Should().Be(expectedSize);

        // Verify logging
        var logs = _fakeLogger.Collector.GetSnapshot();
        logs.Should().Contain(log => 
            log.Level == LogLevel.Debug && 
            log.Message.Contains($"Performing ECDH key agreement on curve {curveName}"));
    }

    [Test]
    [Category("InputValidation")]
    public void PerformKeyAgreement_NullPrivateKey_ThrowsArgumentNullException()
    {
        // Arrange
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256();
        var (_, publicKey) = GenerateKeyPair("P-256");

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            ecdh.PerformKeyAgreement(null!, publicKey.Q.GetEncoded(false)));
    }

    [Test]
    [Category("InputValidation")]
    public void PerformKeyAgreement_NullPublicKey_ThrowsArgumentNullException()
    {
        // Arrange
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256();
        var (privateKey, _) = GenerateKeyPair("P-256");

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            ecdh.PerformKeyAgreement(privateKey.D.ToByteArrayUnsigned(), null!));
    }

    [Test]
    [Category("InputValidation")]
    public void PerformKeyAgreement_InvalidPrivateKey_ThrowsInvalidPrivateKeyException()
    {
        // Arrange
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256();
        var (_, publicKey) = GenerateKeyPair("P-256");
        var invalidPrivateKey = new byte[] { 0x00 }; // Zero

        // Act & Assert
        var ex = Assert.Throws<PrivateKeyZeroException>(() =>
            ecdh.PerformKeyAgreement(invalidPrivateKey, publicKey.Q.GetEncoded(false)));
        ex!.Message.Should().Contain("zero");
    }

    [Test]
    [Category("InputValidation")]
    public void PerformKeyAgreement_InvalidPublicKey_ThrowsInvalidPublicKeyException()
    {
        // Arrange
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256();
        var (privateKey, _) = GenerateKeyPair("P-256");
        var invalidPublicKey = new byte[] { 0x04, 0x00, 0x01 }; // Too short

        // Act & Assert
        var ex = Assert.Throws<PublicKeyInvalidLengthException>(() =>
            ecdh.PerformKeyAgreement(privateKey.D.ToByteArrayUnsigned(), invalidPublicKey));
        ex!.Message.Should().Contain("incorrect length");
    }

    [Test]
    public void PerformKeyAgreement_PublicKeyAtInfinity_ThrowsInvalidPublicKeyException()
    {
        // Arrange
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256();
        var (privateKey, _) = GenerateKeyPair("P-256");
        
        // Create a proper point at infinity encoding for P-256
        // The infinity point encoding is just 0x00, which will be caught by length check
        // So we'll create a zero point which will pass length but fail validation
        var zeroPoint = new byte[65]; // Correct length for P-256
        zeroPoint[0] = 0x04; // Uncompressed format
        // Rest is zeros, representing (0,0) which is not on the curve

        // Act & Assert
        var ex = Assert.Throws<PublicKeyDecodingException>(() =>
            ecdh.PerformKeyAgreement(privateKey.D.ToByteArrayUnsigned(), zeroPoint));
        // This will fail with DecodingFailed because (0,0) is not a valid point
        ex!.Message.Should().Contain("decode");
    }

    [Test]
    [Category("InputValidation")]
    public void PerformKeyAgreement_InvalidPublicKeyFormat_ThrowsInvalidPublicKeyException()
    {
        // Arrange
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256();
        var (privateKey, _) = GenerateKeyPair("P-256");
        
        // Create a public key with invalid format (not 0x04)
        var invalidPublicKey = new byte[65]; // Correct length for P-256
        invalidPublicKey[0] = 0x02; // Compressed format, which we don't support
        Array.Fill<byte>(invalidPublicKey, 0x01, 1, 64);

        // Act & Assert
        var ex = Assert.Throws<PublicKeyInvalidFormatException>(() =>
            ecdh.PerformKeyAgreement(privateKey.D.ToByteArrayUnsigned(), invalidPublicKey));
        ex!.Message.Should().Contain("0x02");
    }

    [Test]
    [Category("InputValidation")]
    public void PerformKeyAgreement_ShortInfinityEncoding_ThrowsInvalidPublicKeyException()
    {
        // Arrange
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256();
        var (privateKey, _) = GenerateKeyPair("P-256");
        
        // The point at infinity is encoded as a single byte 0x00 in some implementations
        var infinityEncoded = new byte[] { 0x00 };

        // Act & Assert
        var ex = Assert.Throws<PublicKeyInvalidLengthException>(() =>
            ecdh.PerformKeyAgreement(privateKey.D.ToByteArrayUnsigned(), infinityEncoded));
        // This will fail with InvalidLength because it's too short
        ex!.Message.Should().Contain("incorrect length");
    }

    [Test]
    public void ValidateKeys_ValidKeyPair_ReturnsTrue()
    {
        // Arrange
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP384();
        var (privateKey, publicKey) = GenerateKeyPair("P-384");

        // Act
        var result = ecdh.ValidateKeys(
            privateKey.D.ToByteArrayUnsigned(),
            publicKey.Q.GetEncoded(false));

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void ValidateKeys_InvalidKeys_ReturnsFalse()
    {
        // Arrange
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256();

        // Act & Assert
        ecdh.ValidateKeys(new byte[] { 0x00 }, new byte[] { 0x04, 0x00 }).Should().BeFalse();
    }

    [TestCase("P-256", 256)]
    [TestCase("P-384", 384)]
    [TestCase("P-521", 521)]
    public void SharedSecretSize_ReturnsCorrectSize(string curveName, int expectedBits)
    {
        // Arrange
        var ecdh = CreateEcdhForCurve(curveName);

        // Act
        var size = ecdh.SharedSecretSize;

        // Assert
        size.Should().Be(expectedBits);
    }

    [TestCase("P-256", "ECDH-P-256")]
    [TestCase("P-384", "ECDH-P-384")]
    [TestCase("P-521", "ECDH-P-521")]
    public void SchemeName_ReturnsCorrectName(string curveName, string expectedName)
    {
        // Arrange
        var ecdh = CreateEcdhForCurve(curveName);

        // Act
        var name = ecdh.SchemeName;

        // Assert
        name.Should().Be(expectedName);
    }

    [Test]
    public void PerformKeyAgreement_WithPaddedOutput_GeneratesConsistentLength()
    {
        // Arrange
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256();
        var expectedLength = 32; // 256 bits / 8

        // Perform multiple key agreements to ensure consistent padding
        for (int i = 0; i < 10; i++)
        {
            var (privateKey, _) = GenerateKeyPair("P-256");
            var (_, publicKey) = GenerateKeyPair("P-256");

            // Act
            var sharedSecret = ecdh.PerformKeyAgreement(
                privateKey.D.ToByteArrayUnsigned(),
                publicKey.Q.GetEncoded(false));

            // Assert
            sharedSecret.Length.Should().Be(expectedLength);
        }
    }

    [Test]
    public void PerformKeyAgreement_LogsWarningsForInvalidKeys()
    {
        // Arrange
        var logger = _fakeLogger;
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256(logger);
        var (privateKey, _) = GenerateKeyPair("P-256");

        // Create an invalid public key (not on curve)
        var invalidPoint = new byte[65];
        invalidPoint[0] = 0x04; // Uncompressed
        Array.Fill<byte>(invalidPoint, 0xFF, 1, 64); // Invalid coordinates

        // Act & Assert
        var ex = Assert.Throws<PublicKeyDecodingException>(() =>
            ecdh.PerformKeyAgreement(privateKey.D.ToByteArrayUnsigned(), invalidPoint));

        // Verify error was logged
        var logs = _fakeLogger.Collector.GetSnapshot();
        logs.Should().Contain(log => 
            log.Level == LogLevel.Error &&
            log.Message.Contains("Failed to decode public key"));
    }

    private Sp80056AEcdhKeyAgreement CreateEcdhForCurve(string curveName, ILogger<Sp80056AEcdhKeyAgreement>? logger = null)
    {
        return curveName switch
        {
            "P-256" => Sp80056AEcdhKeyAgreement.CreateP256(logger),
            "P-384" => Sp80056AEcdhKeyAgreement.CreateP384(logger),
            "P-521" => Sp80056AEcdhKeyAgreement.CreateP521(logger),
            _ => throw new ArgumentException($"Unknown curve: {curveName}")
        };
    }

    private (ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey) GenerateKeyPair(string curveName)
    {
        var curve = ECNamedCurveTable.GetByName(curveName);
        var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        var keyGen = new ECKeyPairGenerator();
        keyGen.Init(new ECKeyGenerationParameters(domainParams, _random));
        var keyPair = keyGen.GenerateKeyPair();

        return (
            (ECPrivateKeyParameters)keyPair.Private,
            (ECPublicKeyParameters)keyPair.Public
        );
    }
}
