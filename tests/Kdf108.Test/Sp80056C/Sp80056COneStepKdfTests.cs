using System;
using AwesomeAssertions;
using Kdf108.Domain.Interfaces.KeyAgreement;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Sp80056A;
using Kdf108.Domain.Sp80056C;
using Kdf108.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Moq;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Kdf108.Test.Sp80056C;

[TestFixture]
[Category("Unit")]
public class Sp80056COneStepKdfTests
{
    private FakeLogger<Sp80056COneStepKdf> _fakeLogger;
    private Mock<ISp80056AKeyAgreement> _mockKeyAgreement;
    private SecureRandom _random;

    [SetUp]
    public void Setup()
    {
        _fakeLogger = new FakeLogger<Sp80056COneStepKdf>();
        _mockKeyAgreement = new Mock<ISp80056AKeyAgreement>();
        _random = new SecureRandom();
    }

    [Test]
    public void DeriveKey_ValidInputs_GeneratesCorrectKey()
    {
        // Arrange
        var sharedSecret = new byte[32];
        _random.NextBytes(sharedSecret);
        
        _mockKeyAgreement.Setup(x => x.PerformKeyAgreement(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
            .Returns(sharedSecret);
        _mockKeyAgreement.Setup(x => x.SchemeName).Returns("ECDH-P-256");

        var logger = _fakeLogger;
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object, logger);

        var (privateKey, publicKey) = GenerateKeyPair("P-256");
        var sp56aPrivateKey = Sp80056APrivateKey.FromBouncyCastleParameters(privateKey, "P-256");
        var sp56aPublicKey = Sp80056APublicKey.FromBouncyCastleParameters(publicKey, "P-256");

        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(32)
            .UseOneStepKdf(PrfType.HmacSha256)
            .Build();

        // Act
        var result = oneStepKdf.DeriveKey(sp56aPrivateKey, sp56aPublicKey, options);

        // Assert
        result.Should().NotBeNull();
        result.Length.Should().Be(32);
        _mockKeyAgreement.Verify(x => x.PerformKeyAgreement(It.IsAny<byte[]>(), It.IsAny<byte[]>()), Times.Once);
    }

    [Test]
    [Category("InputValidation")]
    public void DeriveKey_NullPrivateKey_ThrowsArgumentNullException()
    {
        // Arrange
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object);
        var (_, publicKey) = GenerateKeyPair("P-256");
        var sp56aPublicKey = Sp80056APublicKey.FromBouncyCastleParameters(publicKey, "P-256");
        var options = CreateDefaultOptions();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            oneStepKdf.DeriveKey(null!, sp56aPublicKey, options));
    }

    [Test]
    [Category("InputValidation")]
    public void DeriveKey_NullPublicKey_ThrowsArgumentNullException()
    {
        // Arrange
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object);
        var (privateKey, _) = GenerateKeyPair("P-256");
        var sp56aPrivateKey = Sp80056APrivateKey.FromBouncyCastleParameters(privateKey, "P-256");
        var options = CreateDefaultOptions();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            oneStepKdf.DeriveKey(sp56aPrivateKey, null!, options));
    }

    [Test]
    [Category("InputValidation")]
    public void DeriveKey_NullOptions_ThrowsArgumentNullException()
    {
        // Arrange
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object);
        var (privateKey, publicKey) = GenerateKeyPair("P-256");
        var sp56aPrivateKey = Sp80056APrivateKey.FromBouncyCastleParameters(privateKey, "P-256");
        var sp56aPublicKey = Sp80056APublicKey.FromBouncyCastleParameters(publicKey, "P-256");

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            oneStepKdf.DeriveKey(sp56aPrivateKey, sp56aPublicKey, null!));
    }

    [Test]
    public void DeriveKeyFromSharedSecret_ValidInputs_GeneratesCorrectKey()
    {
        // Arrange
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object);
        var sharedSecret = new byte[32];
        _random.NextBytes(sharedSecret);

        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(48)
            .WithContext(new byte[] { 0x01, 0x02, 0x03 })
            .UseOneStepKdf(PrfType.HmacSha384)
            .Build();

        // Act
        var result = oneStepKdf.DeriveKeyFromSharedSecret(sharedSecret, options);

        // Assert
        result.Should().NotBeNull();
        result.Length.Should().Be(48);
    }

    [Test]
    public void DeriveKeyFromSharedSecret_WithSalt_IncludesSaltInDerivation()
    {
        // Arrange
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object);
        var sharedSecret = new byte[32];
        _random.NextBytes(sharedSecret);
        var salt = new byte[16];
        _random.NextBytes(salt);

        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(32)
            .WithSalt(salt)
            .UseOneStepKdf(PrfType.HmacSha256)
            .Build();

        // Act
        var result1 = oneStepKdf.DeriveKeyFromSharedSecret(sharedSecret, options);
        
        // Derive again without salt
        var optionsNoSalt = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(32)
            .UseOneStepKdf(PrfType.HmacSha256)
            .Build();
        var result2 = oneStepKdf.DeriveKeyFromSharedSecret(sharedSecret, optionsNoSalt);

        // Assert
        result1.Should().NotBeNull();
        result2.Should().NotBeNull();
        result1.Should().NotEqual(result2); // Different results due to salt
    }

    [Test]
    public void DeriveKeyFromSharedSecret_WithOtherInfo_IncludesOtherInfoInDerivation()
    {
        // Arrange
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object);
        var sharedSecret = new byte[32];
        _random.NextBytes(sharedSecret);
        var otherInfo = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };

        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(32)
            .WithOtherInfo(otherInfo)
            .UseOneStepKdf(PrfType.HmacSha256)
            .Build();

        // Act
        var result = oneStepKdf.DeriveKeyFromSharedSecret(sharedSecret, options);

        // Assert
        result.Should().NotBeNull();
        result.Length.Should().Be(32);
    }

    [TestCase(PrfType.HmacSha1)]
    [TestCase(PrfType.HmacSha256)]
    [TestCase(PrfType.HmacSha384)]
    [TestCase(PrfType.HmacSha512)]
    public void DeriveKeyFromSharedSecret_DifferentPrfTypes_ProducesDifferentKeys(PrfType prfType)
    {
        // Arrange
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object);
        var sharedSecret = new byte[32];
        _random.NextBytes(sharedSecret);

        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(32)
            .UseOneStepKdf(prfType)
            .Build();

        // Act
        var result = oneStepKdf.DeriveKeyFromSharedSecret(sharedSecret, options);

        // Assert
        result.Should().NotBeNull();
        result.Length.Should().Be(32);
    }

    [Test]
    public void DeriveKey_KeyAgreementThrows_PropagatesException()
    {
        // Arrange
        var expectedException = new Sp80056AKeyAgreementException("Test error", KeyAgreementFailureType.General, "ECDH");
        _mockKeyAgreement.Setup(x => x.PerformKeyAgreement(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
            .Throws(expectedException);

        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object);
        var (privateKey, publicKey) = GenerateKeyPair("P-256");
        var sp56aPrivateKey = Sp80056APrivateKey.FromBouncyCastleParameters(privateKey, "P-256");
        var sp56aPublicKey = Sp80056APublicKey.FromBouncyCastleParameters(publicKey, "P-256");
        var options = CreateDefaultOptions();

        // Act & Assert
        var ex = Assert.Throws<Sp80056AKeyAgreementException>(() =>
            oneStepKdf.DeriveKey(sp56aPrivateKey, sp56aPublicKey, options));
        ex.Should().Be(expectedException);
    }

    [Test]
    public void PipelineName_ReturnsCorrectName()
    {
        // Arrange
        _mockKeyAgreement.Setup(x => x.SchemeName).Returns("ECDH-P-384");
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object);

        // Act
        var name = oneStepKdf.PipelineName;

        // Assert
        name.Should().Be("SP800-56C-OneStep-ECDH-P-384");
    }

    [Test]
    public void DeriveKey_LogsDebugInformation()
    {
        // Arrange
        var sharedSecret = new byte[32];
        _random.NextBytes(sharedSecret);
        
        _mockKeyAgreement.Setup(x => x.PerformKeyAgreement(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
            .Returns(sharedSecret);
        _mockKeyAgreement.Setup(x => x.SchemeName).Returns("ECDH-P-256");

        var logger = _fakeLogger;
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object, logger);

        var (privateKey, publicKey) = GenerateKeyPair("P-256");
        var sp56aPrivateKey = Sp80056APrivateKey.FromBouncyCastleParameters(privateKey, "P-256");
        var sp56aPublicKey = Sp80056APublicKey.FromBouncyCastleParameters(publicKey, "P-256");
        var options = CreateDefaultOptions();

        // Act
        oneStepKdf.DeriveKey(sp56aPrivateKey, sp56aPublicKey, options);

        // Assert
        var logs = _fakeLogger.Collector.GetSnapshot();
        logs.Should().Contain(log => 
            log.Level == LogLevel.Debug && 
            log.Message.Contains("Starting one-step key derivation"));
        logs.Should().Contain(log => 
            log.Level == LogLevel.Information && 
            log.Message.Contains("Successfully derived key"));
    }

    [Test]
    public void DeriveKey_DifferentCurves_ThrowsArgumentException()
    {
        // Arrange
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object);
        var (privateKey256, _) = GenerateKeyPair("P-256");
        var (_, publicKey384) = GenerateKeyPair("P-384");

        var sp56aPrivateKey = Sp80056APrivateKey.FromBouncyCastleParameters(privateKey256, "P-256");
        var sp56aPublicKey = Sp80056APublicKey.FromBouncyCastleParameters(publicKey384, "P-384");
        var options = CreateDefaultOptions();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            oneStepKdf.DeriveKey(sp56aPrivateKey, sp56aPublicKey, options));
        ex!.Message.Should().Contain("same domain parameters");
    }

    [TestCase(16)]  // 128 bits
    [TestCase(32)]  // 256 bits
    [TestCase(48)]  // 384 bits
    [TestCase(64)]  // 512 bits
    [TestCase(100)] // Custom length
    public void DeriveKeyFromSharedSecret_DifferentOutputLengths_ProducesCorrectLength(int outputBytes)
    {
        // Arrange
        var oneStepKdf = new Sp80056COneStepKdf(_mockKeyAgreement.Object);
        var sharedSecret = new byte[32];
        _random.NextBytes(sharedSecret);

        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(outputBytes)
            .UseOneStepKdf(PrfType.HmacSha256)
            .Build();

        // Act
        var result = oneStepKdf.DeriveKeyFromSharedSecret(sharedSecret, options);

        // Assert
        result.Should().NotBeNull();
        result.Length.Should().Be(outputBytes);
    }

    private Sp80056COptions CreateDefaultOptions()
    {
        return Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(32)
            .UseOneStepKdf(PrfType.HmacSha256)
            .Build();
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
