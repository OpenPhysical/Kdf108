// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#pragma warning disable CS1591

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Kdf108.Domain.Kdf;

namespace Kdf108.Domain.Sp80056C;

/// <summary>Approved hash functions listed by SP 800-56C Rev. 2.</summary>
public enum NistHashAlgorithm
{
    Sha1,
    Sha224,
    Sha256,
    Sha512_224,
    Sha512_256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512
}

/// <summary>A target security strength accepted by SP 800-56A Rev. 3.</summary>
public readonly record struct SecurityStrength
{
    private SecurityStrength(int bits) => Bits = bits;

    public int Bits { get; }

    public static SecurityStrength Bits112 { get; } = new(112);
    public static SecurityStrength Bits128 { get; } = new(128);
    public static SecurityStrength Bits152 { get; } = new(152);
    public static SecurityStrength Bits176 { get; } = new(176);
    public static SecurityStrength Bits192 { get; } = new(192);
    public static SecurityStrength Bits200 { get; } = new(200);
    public static SecurityStrength Bits256 { get; } = new(256);
}

/// <summary>A positive bit length.</summary>
public readonly record struct BitLength
{
    private BitLength(long bits) => Bits = bits;

    public long Bits { get; }

    public int ByteLength => checked((int)((Bits + 7) / 8));

    public static BitLength Create(long bits)
    {
        if (bits <= 0)
            throw new ArgumentOutOfRangeException(nameof(bits), bits, "Bit length must be positive.");
        return new BitLength(bits);
    }
}

/// <summary>The auxiliary function used by the SP 800-56C one-step method.</summary>
public abstract class OneStepAuxiliaryFunction : IDisposable
{
    private OneStepAuxiliaryFunction() { }

    public virtual void Dispose() { }

    public sealed class Hash : OneStepAuxiliaryFunction
    {
        internal Hash(NistHashAlgorithm algorithm) => Algorithm = algorithm;
        public NistHashAlgorithm Algorithm { get; }
    }

    public sealed class Hmac : OneStepAuxiliaryFunction
    {
        private readonly byte[]? _salt;
        private bool _disposed;

        internal Hmac(NistHashAlgorithm algorithm, byte[]? salt)
        {
            Algorithm = algorithm;
            _salt = salt?.ToArray();
        }

        public NistHashAlgorithm Algorithm { get; }
        public bool UsesDefaultSalt => _salt is null;
        internal byte[]? CopySalt() { ObjectDisposedException.ThrowIf(_disposed, this); return _salt?.ToArray(); }
        public override void Dispose() { if (_disposed) return; if (_salt is not null) CryptographicOperations.ZeroMemory(_salt); _disposed = true; }
    }

    public sealed class Kmac : OneStepAuxiliaryFunction
    {
        private readonly byte[]? _salt;
        private bool _disposed;

        internal Kmac(int strength, BitLength outputLength, byte[]? salt)
        {
            Strength = strength;
            OutputLength = outputLength;
            _salt = salt?.ToArray();
        }

        public int Strength { get; }
        public BitLength OutputLength { get; }
        public bool UsesDefaultSalt => _salt is null;
        internal byte[]? CopySalt() { ObjectDisposedException.ThrowIf(_disposed, this); return _salt?.ToArray(); }
        public override void Dispose() { if (_disposed) return; if (_salt is not null) CryptographicOperations.ZeroMemory(_salt); _disposed = true; }
    }

    public static OneStepAuxiliaryFunction HashFunction(NistHashAlgorithm algorithm) => new Hash(algorithm);

    public static OneStepAuxiliaryFunction HmacFunction(NistHashAlgorithm algorithm, ReadOnlySpan<byte> salt = default)
        => new Hmac(algorithm, salt.IsEmpty ? null : salt.ToArray());

    public static OneStepAuxiliaryFunction Kmac128(BitLength outputLength, ReadOnlySpan<byte> salt = default)
        => CreateKmac(128, outputLength, salt);

    public static OneStepAuxiliaryFunction Kmac256(BitLength outputLength, ReadOnlySpan<byte> salt = default)
        => CreateKmac(256, outputLength, salt);

    private static OneStepAuxiliaryFunction CreateKmac(int strength, BitLength outputLength, ReadOnlySpan<byte> salt)
    {
        if (outputLength.Bits != 160 && outputLength.Bits != 224 && outputLength.Bits != 256 &&
            outputLength.Bits != 384 && outputLength.Bits != 512)
        {
            // L itself is also permitted. That relationship is checked by OneStepKdfRequest.
            if (outputLength.Bits <= 0)
                throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        return new Kmac(strength, outputLength, salt.IsEmpty ? null : salt.ToArray());
    }
}

/// <summary>Immutable input for the SP 800-56C Rev. 2 one-step method.</summary>
public sealed class OneStepKdfRequest : IDisposable
{
    private readonly byte[] _sharedSecret;
    private readonly byte[] _fixedInfo;
    private bool _disposed;

    public OneStepKdfRequest(
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> fixedInfo,
        BitLength outputLength,
        SecurityStrength securityStrength,
        OneStepAuxiliaryFunction auxiliaryFunction)
    {
        if (sharedSecret.IsEmpty)
            throw new ArgumentException("The shared secret must not be empty.", nameof(sharedSecret));

        AuxiliaryFunction = auxiliaryFunction ?? throw new ArgumentNullException(nameof(auxiliaryFunction));
        ValidateStrength(auxiliaryFunction, securityStrength);

        if (auxiliaryFunction is OneStepAuxiliaryFunction.Kmac kmac &&
            kmac.OutputLength.Bits != outputLength.Bits &&
            kmac.OutputLength.Bits is not (160 or 224 or 256 or 384 or 512))
        {
            throw new ArgumentException("KMAC output length must be L or one of 160, 224, 256, 384, or 512 bits.", nameof(auxiliaryFunction));
        }

        _sharedSecret = sharedSecret.ToArray();
        _fixedInfo = fixedInfo.ToArray();
        OutputLength = outputLength;
        SecurityStrength = securityStrength;
    }

    public BitLength OutputLength { get; }
    public SecurityStrength SecurityStrength { get; }
    public OneStepAuxiliaryFunction AuxiliaryFunction { get; }
    internal byte[] CopySharedSecret() { ThrowIfDisposed(); return _sharedSecret.ToArray(); }
    internal byte[] CopyFixedInfo() { ThrowIfDisposed(); return _fixedInfo.ToArray(); }

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_sharedSecret);
        AuxiliaryFunction.Dispose();
        _disposed = true;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private static void ValidateStrength(OneStepAuxiliaryFunction function, SecurityStrength strength)
    {
        int maximum = function switch
        {
            OneStepAuxiliaryFunction.Hash hash => Sp80056CAlgorithmInfo.OutputBits(hash.Algorithm),
            OneStepAuxiliaryFunction.Hmac hmac => Sp80056CAlgorithmInfo.OutputBits(hmac.Algorithm),
            OneStepAuxiliaryFunction.Kmac { Strength: 128 } => 128,
            OneStepAuxiliaryFunction.Kmac { Strength: 256 } => 256,
            _ => throw new ArgumentOutOfRangeException(nameof(function))
        };

        if (strength.Bits < 112 || strength.Bits > maximum)
            throw new ArgumentException($"The auxiliary function cannot support {strength.Bits}-bit security.", nameof(strength));
    }
}

/// <summary>The permitted extraction choices for the two-step method.</summary>
public abstract class TwoStepExtraction : IDisposable
{
    private TwoStepExtraction() { }

    public abstract void Dispose();

    public sealed class Hmac : TwoStepExtraction
    {
        private readonly byte[]? _salt;
        private bool _disposed;
        internal Hmac(NistHashAlgorithm algorithm, byte[]? salt) { Algorithm = algorithm; _salt = salt?.ToArray(); }
        public NistHashAlgorithm Algorithm { get; }
        internal byte[]? CopySalt() { ObjectDisposedException.ThrowIf(_disposed, this); return _salt?.ToArray(); }
        public override void Dispose() { if (_disposed) return; if (_salt is not null) CryptographicOperations.ZeroMemory(_salt); _disposed = true; }
    }

    public sealed class AesCmac : TwoStepExtraction
    {
        private readonly byte[]? _salt;
        private bool _disposed;
        internal AesCmac(int keyBits, byte[]? salt) { KeyBits = keyBits; _salt = salt?.ToArray(); }
        public int KeyBits { get; }
        internal byte[]? CopySalt() { ObjectDisposedException.ThrowIf(_disposed, this); return _salt?.ToArray(); }
        public override void Dispose() { if (_disposed) return; if (_salt is not null) CryptographicOperations.ZeroMemory(_salt); _disposed = true; }
    }

    public static TwoStepExtraction HmacFunction(NistHashAlgorithm algorithm, ReadOnlySpan<byte> salt = default)
        => new Hmac(algorithm, salt.IsEmpty ? null : salt.ToArray());

    public static TwoStepExtraction AesCmacFunction(int keyBits, ReadOnlySpan<byte> salt = default)
    {
        if (keyBits is not (128 or 192 or 256))
            throw new ArgumentOutOfRangeException(nameof(keyBits), keyBits, "AES-CMAC extraction requires a 128, 192, or 256-bit key.");
        if (!salt.IsEmpty && salt.Length * 8 != keyBits)
            throw new ArgumentException("AES-CMAC salt must have the selected AES key size.", nameof(salt));
        return new AesCmac(keyBits, salt.IsEmpty ? null : salt.ToArray());
    }
}

/// <summary>A valid SP 800-108 expansion configuration for two-step derivation.</summary>
public abstract class KeyExpansion
{
    private readonly byte[] _fixedInfo;
    private readonly byte[]? _iv;

    private KeyExpansion(ReadOnlySpan<byte> fixedInfo, BitLength outputLength, int counterBits, bool useCounter, CounterLocation counterLocation, byte[]? iv)
    {
        if (counterBits is < 1 or > 32)
            throw new ArgumentOutOfRangeException(nameof(counterBits), counterBits, "Counter length must be between 1 and 32 bits.");
        _fixedInfo = fixedInfo.ToArray();
        _iv = iv?.ToArray();
        OutputLength = outputLength;
        CounterBits = counterBits;
        UseCounter = useCounter;
        CounterLocation = counterLocation;
    }

    public BitLength OutputLength { get; }
    public int CounterBits { get; }
    public bool UseCounter { get; }
    public CounterLocation CounterLocation { get; }
    internal byte[] CopyFixedInfo() => _fixedInfo.ToArray();
    internal byte[]? CopyIv() => _iv?.ToArray();

    public sealed class Counter : KeyExpansion
    {
        internal Counter(ReadOnlySpan<byte> fixedInfo, BitLength outputLength, int counterBits, CounterLocation counterLocation)
            : base(fixedInfo, outputLength, counterBits, true, counterLocation, null) { }
    }

    public sealed class Feedback : KeyExpansion
    {
        internal Feedback(ReadOnlySpan<byte> fixedInfo, ReadOnlySpan<byte> iv, BitLength outputLength, int counterBits, bool useCounter, CounterLocation counterLocation)
            : base(fixedInfo, outputLength, counterBits, useCounter, counterLocation, iv.ToArray()) { }
    }

    public sealed class DoublePipeline : KeyExpansion
    {
        internal DoublePipeline(ReadOnlySpan<byte> fixedInfo, BitLength outputLength, int counterBits, bool useCounter, CounterLocation counterLocation)
            : base(fixedInfo, outputLength, counterBits, useCounter, counterLocation, null) { }
    }

    public static KeyExpansion CounterMode(ReadOnlySpan<byte> fixedInfo, BitLength outputLength, int counterBits = 32, CounterLocation counterLocation = CounterLocation.BeforeFixed)
        => new Counter(fixedInfo, outputLength, counterBits, counterLocation);

    public static KeyExpansion FeedbackMode(ReadOnlySpan<byte> fixedInfo, ReadOnlySpan<byte> iv, BitLength outputLength, bool useCounter = true, int counterBits = 32, CounterLocation counterLocation = CounterLocation.BeforeFixed)
        => new Feedback(fixedInfo, iv, outputLength, counterBits, useCounter, counterLocation);

    public static KeyExpansion DoublePipelineMode(ReadOnlySpan<byte> fixedInfo, BitLength outputLength, bool useCounter = true, int counterBits = 32, CounterLocation counterLocation = CounterLocation.BeforeFixed)
        => new DoublePipeline(fixedInfo, outputLength, counterBits, useCounter, counterLocation);
}

/// <summary>Immutable input for SP 800-56C Rev. 2 two-step derivation.</summary>
public sealed class TwoStepKdfRequest : IDisposable
{
    private readonly byte[] _sharedSecret;
    private readonly KeyExpansion[] _expansions;
    private bool _disposed;

    public TwoStepKdfRequest(ReadOnlySpan<byte> sharedSecret, TwoStepExtraction extraction, SecurityStrength securityStrength, IEnumerable<KeyExpansion> expansions)
    {
        if (sharedSecret.IsEmpty)
            throw new ArgumentException("The shared secret must not be empty.", nameof(sharedSecret));
        Extraction = extraction ?? throw new ArgumentNullException(nameof(extraction));
        _expansions = expansions?.ToArray() ?? throw new ArgumentNullException(nameof(expansions));
        if (_expansions.Length == 0)
            throw new ArgumentException("At least one expansion is required.", nameof(expansions));

        var duplicateFixedInfo = _expansions
            .Select(x => Convert.ToHexString(x.CopyFixedInfo()))
            .GroupBy(x => x, StringComparer.Ordinal)
            .Any(group => group.Count() > 1);
        if (duplicateFixedInfo)
            throw new ArgumentException("FixedInfo values must be pairwise distinct.", nameof(expansions));

        int maximumStrength = extraction switch
        {
            TwoStepExtraction.Hmac hmac => Sp80056CAlgorithmInfo.OutputBits(hmac.Algorithm),
            TwoStepExtraction.AesCmac => 128,
            _ => throw new ArgumentOutOfRangeException(nameof(extraction))
        };
        if (securityStrength.Bits < 112 || securityStrength.Bits > maximumStrength)
            throw new ArgumentException($"The extraction function cannot support {securityStrength.Bits}-bit security.", nameof(securityStrength));

        _sharedSecret = sharedSecret.ToArray();
        SecurityStrength = securityStrength;
    }

    public TwoStepExtraction Extraction { get; }
    public SecurityStrength SecurityStrength { get; }
    public IReadOnlyList<KeyExpansion> Expansions => Array.AsReadOnly(_expansions);
    internal byte[] CopySharedSecret() { ThrowIfDisposed(); return _sharedSecret.ToArray(); }

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_sharedSecret);
        Extraction.Dispose();
        _disposed = true;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

internal static class Sp80056CAlgorithmInfo
{
    internal static int OutputBits(NistHashAlgorithm algorithm) => algorithm switch
    {
        NistHashAlgorithm.Sha1 => 160,
        NistHashAlgorithm.Sha224 or NistHashAlgorithm.Sha512_224 or NistHashAlgorithm.Sha3_224 => 224,
        NistHashAlgorithm.Sha256 or NistHashAlgorithm.Sha512_256 or NistHashAlgorithm.Sha3_256 => 256,
        NistHashAlgorithm.Sha384 or NistHashAlgorithm.Sha3_384 => 384,
        NistHashAlgorithm.Sha512 or NistHashAlgorithm.Sha3_512 => 512,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };

    internal static int BlockBytes(NistHashAlgorithm algorithm) => algorithm switch
    {
        NistHashAlgorithm.Sha1 or NistHashAlgorithm.Sha224 or NistHashAlgorithm.Sha256 => 64,
        NistHashAlgorithm.Sha512_224 or NistHashAlgorithm.Sha512_256 or NistHashAlgorithm.Sha384 or NistHashAlgorithm.Sha512 => 128,
        NistHashAlgorithm.Sha3_224 => 144,
        NistHashAlgorithm.Sha3_256 => 136,
        NistHashAlgorithm.Sha3_384 => 104,
        NistHashAlgorithm.Sha3_512 => 72,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };

    internal static PrfType ToPrf(NistHashAlgorithm algorithm) => algorithm switch
    {
        NistHashAlgorithm.Sha1 => PrfType.HmacSha1,
        NistHashAlgorithm.Sha224 => PrfType.HmacSha224,
        NistHashAlgorithm.Sha256 => PrfType.HmacSha256,
        NistHashAlgorithm.Sha384 => PrfType.HmacSha384,
        NistHashAlgorithm.Sha512 => PrfType.HmacSha512,
        NistHashAlgorithm.Sha512_224 => PrfType.HmacSha512_224,
        NistHashAlgorithm.Sha512_256 => PrfType.HmacSha512_256,
        NistHashAlgorithm.Sha3_224 => PrfType.HmacSha3_224,
        NistHashAlgorithm.Sha3_256 => PrfType.HmacSha3_256,
        NistHashAlgorithm.Sha3_384 => PrfType.HmacSha3_384,
        NistHashAlgorithm.Sha3_512 => PrfType.HmacSha3_512,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };
}
