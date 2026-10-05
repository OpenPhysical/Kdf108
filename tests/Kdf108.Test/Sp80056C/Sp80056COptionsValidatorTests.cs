using System;
using AwesomeAssertions;
using FluentValidation;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Sp80056C;
using Kdf108.Domain.Validator;
using Microsoft.Extensions.Logging.Testing;

namespace Kdf108.Test.Sp80056C;

[TestFixture]
[Category("Unit")]
public class Sp80056COptionsValidatorTests
{
    private Sp80056COptionsValidator _validator;
    private FakeLogger<Sp80056COptionsValidator> _fakeLogger;

    [SetUp]
    public void Setup()
    {
        _fakeLogger = new FakeLogger<Sp80056COptionsValidator>();
        _validator = new Sp80056COptionsValidator(_fakeLogger);
    }

    [Test]
    public void Validate_ValidOneStepOptions_PassesValidation()
    {
        // Arrange
        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(32)
            .UseOneStepKdf(PrfType.HmacSha256)
            .Build();

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Test]
    public void Validate_ValidTwoStepOptions_PassesValidation()
    {
        // Arrange
        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(48)
            .UseTwoStepKdf(PrfType.HmacSha256, PrfType.HmacSha384)
            .Build();

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Test]
    [Category("InputValidation")]
    public void Validate_NullOptions_ThrowsInvalidOperationException()
    {
        // Arrange & Act & Assert
        Assert.Throws<InvalidOperationException>(() => _validator.Validate((Sp80056COptions)null!));
    }

    [Test]
    [Category("InputValidation")]
    public void Validate_EmptyLabel_FailsValidation()
    {
        // Arrange
        var options = new Sp80056COptions
        {
            Label = "",
            OutputLengthInBits = 256
        };

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => e.ErrorMessage == "Label must be specified for key derivation");
    }

    [Test]
    [Category("InputValidation")]
    public void Validate_ZeroOutputLength_FailsValidation()
    {
        // Arrange
        var options = new Sp80056COptions
        {
            Label = "TestLabel",
            OutputLengthInBits = 0
        };

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => 
            e.ErrorMessage == "Output length must be positive");
    }

    [Test]
    [Category("InputValidation")]
    public void Validate_NegativeOutputLength_FailsValidation()
    {
        // Arrange
        var options = new Sp80056COptions
        {
            Label = "TestLabel",
            OutputLengthInBits = -100
        };

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => 
            e.ErrorMessage == "Output length must be positive");
    }

    [Test]
    public void Validate_OutputLengthNotMultipleOf8_FailsValidation()
    {
        // Arrange
        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBits(257) // Not a multiple of 8
            .UseOneStepKdf(PrfType.HmacSha256)
            .Build();

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => 
            e.ErrorMessage == "Output length must be a multiple of 8 bits");
    }

    [Test]
    public void Validate_InvalidKdfType_FailsValidation()
    {
        // Arrange
        var options = new Sp80056COptions
        {
            Label = "TestLabel",
            OutputLengthInBits = 256,
            UseTwoStep = true,
            ExtractionPrfType = (PrfType)999, // Invalid enum value
            ExpansionPrfType = PrfType.HmacSha256
        };

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => 
            e.ErrorMessage.Contains("Invalid extraction PRF type"));
    }

    [Test]
    public void Validate_CounterLengthTooSmall_FailsValidation()
    {
        // Arrange
        var options = new Sp80056COptions
        {
            Label = "TestLabel",
            OutputLengthInBits = 256,
            CounterLengthBits = 0 // Too small
        };

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => 
            e.ErrorMessage == "Counter length must be between 1 and 32 bits");
    }

    [Test]
    public void Validate_CounterLengthNotMultipleOf8_PassesValidation()
    {
        // Arrange
        var options = new Sp80056COptions
        {
            Label = "TestLabel",
            OutputLengthInBits = 256,
            CounterLengthBits = 12
        };

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Test]
    public void Validate_TwoStepWithoutExtractionPrf_FailsValidation()
    {
        // Arrange
        var options = new Sp80056COptions
        {
            Label = "TestLabel",
            OutputLengthInBits = 256,
            UseTwoStep = true,
            ExtractionPrfType = (PrfType)999, // Invalid extraction PRF
            ExpansionPrfType = PrfType.HmacSha256
        };

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => 
            e.ErrorMessage == "Invalid extraction PRF type specified");
    }

    [Test]
    public void Validate_TwoStepWithoutExpansionPrf_FailsValidation()
    {
        // Arrange
        var options = new Sp80056COptions
        {
            Label = "TestLabel",
            OutputLengthInBits = 256,
            UseTwoStep = true,
            ExtractionPrfType = PrfType.HmacSha256,
            ExpansionPrfType = (PrfType)999 // Invalid expansion PRF
        };

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => 
            e.ErrorMessage == "Invalid expansion PRF type specified");
    }

    [Test]
    public void Validate_ValidOptionsWithSalt_PassesValidation()
    {
        // Arrange
        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(32)
            .WithSalt(new byte[] { 0x01, 0x02, 0x03 })
            .UseOneStepKdf(PrfType.HmacSha256)
            .Build();

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Test]
    public void Validate_ValidOptionsWithContext_PassesValidation()
    {
        // Arrange
        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(32)
            .WithContext(new byte[] { 0xAA, 0xBB, 0xCC })
            .UseOneStepKdf(PrfType.HmacSha256)
            .Build();

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Test]
    public void Validate_ValidOptionsWithOtherInfo_PassesValidation()
    {
        // Arrange
        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(32)
            .WithOtherInfo(new byte[] { 0x11, 0x22, 0x33 })
            .UseOneStepKdf(PrfType.HmacSha256)
            .Build();

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Test]
    public void Validate_LogsDebugInformation()
    {
        // Arrange
        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(64)
            .UseTwoStepKdf(PrfType.HmacSha384, PrfType.HmacSha512)
            .Build();

        // Act
        _validator.Validate(options);

        // Assert
        var logs = _fakeLogger.Collector.GetSnapshot();
        logs.Should().Contain(log => 
            log.Level == Microsoft.Extensions.Logging.LogLevel.Debug &&
            log.Message.Contains("Validating SP 800-56C options"));
    }

    [Test]
    public void ValidateAndThrow_InvalidOptions_ThrowsValidationException()
    {
        // Arrange
        var options = new Sp80056COptions
        {
            Label = "",
            OutputLengthInBits = 256
        };

        // Act & Assert
        Assert.Throws<ValidationException>(() => _validator.ValidateAndThrow(options));
    }

    [Test]
    public void Validate_MultipleErrors_ReturnsAllErrors()
    {
        // Arrange
        var options = new Sp80056COptions
        {
            Label = "", // Empty label
            OutputLengthInBits = 0, // Zero length
            UseTwoStep = true,
            ExtractionPrfType = (PrfType)999, // Invalid extraction PRF
            ExpansionPrfType = (PrfType)998, // Invalid expansion PRF
            CounterLengthBits = 0 // Too small
        };

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().HaveCountGreaterThan(1);
        result.Errors.Should().Contain(e => e.ErrorMessage.Contains("Label"));
        result.Errors.Should().Contain(e => e.ErrorMessage.Contains("Output length"));
        result.Errors.Should().Contain(e => e.ErrorMessage.Contains("Invalid extraction PRF type") || e.ErrorMessage.Contains("Invalid expansion PRF type"));
        result.Errors.Should().Contain(e => e.ErrorMessage.Contains("Counter length"));
    }

    [TestCase(8)]
    [TestCase(16)]
    [TestCase(24)]
    [TestCase(32)]
    public void Validate_ValidCounterLengths_PassValidation(int counterLengthBits)
    {
        // Arrange
        var options = new Sp80056COptions
        {
            Label = "TestLabel",
            OutputLengthInBits = 256,
            CounterLengthBits = counterLengthBits
        };

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [TestCase(KdfMode.Counter)]
    [TestCase(KdfMode.Feedback)]
    [TestCase(KdfMode.DoublePipeline)]
    public void Validate_DifferentKdfModes_PassValidation(KdfMode mode)
    {
        // Arrange
        var options = Sp80056COptions.CreateBuilder()
            .WithLabel("TestLabel")
            .WithOutputLengthInBytes(32)
            .UseOneStepKdf(PrfType.HmacSha256)
            .WithKdfMode(mode)
            .Build();

        // Act
        var result = _validator.Validate(options);

        // Assert
        result.IsValid.Should().BeTrue();
    }
}
