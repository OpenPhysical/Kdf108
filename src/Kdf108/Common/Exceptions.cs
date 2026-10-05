// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108;

/// <summary>The base class for every failure this library reports. Catch it to handle all of them.</summary>
public abstract class Kdf108Exception : Exception
{
    /// <summary>Creates the exception.</summary>
    protected Kdf108Exception(string message, Exception? innerException = null) : base(message, innerException) { }
}

/// <summary>A derivation parameter is outside what the standard allows (length, counter width, salt size, PRF pairing, and so on).</summary>
public sealed class KdfParameterException : Kdf108Exception
{
    /// <summary>Creates the exception.</summary>
    public KdfParameterException(string message, string? parameterName = null) : base(message) => ParameterName = parameterName;

    /// <summary>The name of the offending parameter, when there is one.</summary>
    public string? ParameterName { get; }
}

/// <summary>What failed when a key or domain was rejected.</summary>
public enum KeyFailure
{
    /// <summary>A public key failed SP 800-56A §5.6.2.3 validation (encoding, range, curve or subgroup membership).</summary>
    InvalidPublicKey,
    /// <summary>A private key is outside [1, n - 1] (or [1, q - 1] for FFC).</summary>
    InvalidPrivateKey,
    /// <summary>A supplied public key does not correspond to the supplied private key.</summary>
    KeyPairMismatch,
    /// <summary>Keys from different domains (curves or FFC parameters) were combined.</summary>
    DomainMismatch,
    /// <summary>Domain parameters failed validation or are not approved.</summary>
    InvalidDomain
}

/// <summary>A key, key pair, or domain failed SP 800-56A validation.</summary>
public sealed class InvalidKeyException : Kdf108Exception
{
    /// <summary>Creates the exception.</summary>
    public InvalidKeyException(KeyFailure failure, string message, Exception? innerException = null)
        : base(message, innerException) => Failure = failure;

    /// <summary>The kind of failure.</summary>
    public KeyFailure Failure { get; }
}

/// <summary>Key agreement produced a value SP 800-56A forbids, such as the point at infinity or Z ∈ {0, 1, p - 1}.</summary>
public sealed class KeyAgreementException : Kdf108Exception
{
    /// <summary>Creates the exception.</summary>
    public KeyAgreementException(string message) : base(message) { }
}
