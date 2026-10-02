using System;
using System.Linq;
using AwesomeAssertions;
using FluentValidation;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace Kdf108.Test.Logging;

[TestFixture]
[Category("Unit")]
public class CounterModeKdfLoggingTests
{
    private FakeLogger<CounterModeKdf> _fakeLogger;
    private CounterModeKdf _sut;

    [SetUp]
    public void Setup()
    {
        _fakeLogger = new FakeLogger<CounterModeKdf>();
        _sut = new CounterModeKdf(_fakeLogger);
    }

    [Test]
    public void DeriveKey_Success_LogsInformationLevel()
    {
        // Arrange
        var kdk = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        var label = "test-label";
        var context = new byte[] { 0xFF };
        var outputLengthInBits = 256L;
        var options = new KdfOptions
        {
            PrfType = PrfType.HmacSha256,
            CounterLengthBits = 32,
            UseCounter = true,
            CounterLocation = CounterLocation.BeforeFixed
        };

        // Act
        var result = _sut.DeriveKey(kdk, label, context, outputLengthInBits, options);

        // Assert
        result.Should().NotBeNull();
        result.Length.Should().Be(32); // 256 bits = 32 bytes

        var logs = _fakeLogger.Collector.GetSnapshot();
        logs.Should().Contain(log => 
            log.Level == LogLevel.Debug && 
            log.Message.Contains("Starting Counter Mode KDF derivation"));
        
        logs.Should().Contain(log => 
            log.Level == LogLevel.Information && 
            log.Message.Contains("Successfully derived key"));
    }

    [Test]
    [Category("InputValidation")]
    public void DeriveKey_ValidationFailure_LogsError()
    {
        // Arrange
        var kdk = Array.Empty<byte>(); // Invalid: empty KDK
        var label = "test-label";
        var context = new byte[] { 0xFF };
        var outputLengthInBits = 256L;
        var options = new KdfOptions
        {
            PrfType = PrfType.HmacSha256,
            CounterLengthBits = 32
        };

        // Act & Assert
        Assert.Throws<ValidationException>(() => 
            _sut.DeriveKey(kdk, label, context, outputLengthInBits, options));

        var logs = _fakeLogger.Collector.GetSnapshot();
        logs.Should().Contain(log => 
            log.Level == LogLevel.Error && 
            log.Message.Contains("Validation failed"));
    }

    [Test]
    public void DeriveKey_WithNullLogger_DoesNotThrow()
    {
        // Arrange
        var sutWithoutLogger = new CounterModeKdf(logger: null);
        var kdk = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        var label = "test-label";
        var context = new byte[] { 0xFF };
        var outputLengthInBits = 256L;
        var options = new KdfOptions
        {
            PrfType = PrfType.HmacSha256,
            CounterLengthBits = 32,
            UseCounter = true,
            CounterLocation = CounterLocation.BeforeFixed
        };

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            var result = sutWithoutLogger.DeriveKey(kdk, label, context, outputLengthInBits, options);
            result.Should().NotBeNull();
            result.Length.Should().Be(32);
        });
    }

    [Test]
    public void DeriveKey_LogsCorrectParameters()
    {
        // Arrange
        var kdk = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var label = "specific-label";
        var context = new byte[] { 0xAA, 0xBB };
        var outputLengthInBits = 128L;
        var options = new KdfOptions
        {
            PrfType = PrfType.HmacSha512,
            CounterLengthBits = 16,
            UseCounter = true,
            CounterLocation = CounterLocation.AfterFixed
        };

        // Act
        _sut.DeriveKey(kdk, label, context, outputLengthInBits, options);

        // Assert
        var logs = _fakeLogger.Collector.GetSnapshot();
        var debugLog = logs.FirstOrDefault(log => 
            log.Level == LogLevel.Debug && 
            log.Message.Contains("Starting Counter Mode KDF derivation"));

        debugLog.Should().NotBeNull();
        debugLog!.Message.Should().Contain("specific-label");
        debugLog.Message.Should().Contain("128");
        debugLog.Message.Should().Contain("HmacSha512");
    }

    [Test]
    [Category("InputValidation")]
    public void DeriveKey_ExceptionDuringDerivation_LogsErrorWithException()
    {
        // Arrange
        var kdk = new byte[] { 0x01 };
        var label = "test";
        var context = new byte[] { 0x01 };
        var outputLengthInBits = long.MaxValue; // Unreasonable value to trigger error
        var options = new KdfOptions
        {
            PrfType = PrfType.HmacSha256,
            CounterLengthBits = 8, // Small counter with huge output
            UseCounter = true,
            CounterLocation = CounterLocation.BeforeFixed
        };

        // Act & Assert
        Assert.Throws<ValidationException>(() => 
            _sut.DeriveKey(kdk, label, context, outputLengthInBits, options));

        var logs = _fakeLogger.Collector.GetSnapshot();
        
        // ValidationException should still be logged, but might be at Debug or Information level
        logs.Should().NotBeEmpty();
        var hasValidationError = logs.Any(log => 
            log.Exception != null && 
            log.Exception.GetType() == typeof(ValidationException));
        
        hasValidationError.Should().BeTrue("ValidationException should be logged");
    }
}
