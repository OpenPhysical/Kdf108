// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#pragma warning disable CS1591

using System;
using System.Collections.Generic;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Kdf108.Domain.Sp80056A;

/// <summary>Named safe-prime groups approved by SP 800-56A Rev. 3 Appendix D.</summary>
public enum FfcSafePrimeGroup
{
    Modp2048,
    Modp3072,
    Modp4096,
    Modp6144,
    Modp8192,
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Ffdhe6144,
    Ffdhe8192
}

/// <summary>The assurance obtained for FIPS 186-type domain parameters.</summary>
public abstract class FfcDomainAssurance
{
    private FfcDomainAssurance() { }

    public sealed class GeneratedOrValidated : FfcDomainAssurance
    {
        private readonly byte[] _seed;
        internal GeneratedOrValidated(byte[] seed, int counter) { _seed = seed; Counter = counter; }
        public int Counter { get; }
        public byte[] ExportSeed() => (byte[])_seed.Clone();
    }

    public sealed class TrustedThirdParty : FfcDomainAssurance
    {
        internal TrustedThirdParty(string authority) => Authority = authority;
        public string Authority { get; }
    }

    public static FfcDomainAssurance Fips186GenerationOrValidation(ReadOnlySpan<byte> seed, int counter)
    {
        if (seed.IsEmpty) throw new ArgumentException("FIPS 186 validation evidence requires the generation seed.", nameof(seed));
        if (counter < 0) throw new ArgumentOutOfRangeException(nameof(counter));
        return new GeneratedOrValidated(seed.ToArray(), counter);
    }

    public static FfcDomainAssurance TrustedAuthority(string authority)
    {
        if (string.IsNullOrWhiteSpace(authority)) throw new ArgumentException("The trusted authority must be identified.", nameof(authority));
        return new TrustedThirdParty(authority);
    }
}

/// <summary>A validated finite-field domain.</summary>
public sealed class FfcDomain
{
    private static readonly IReadOnlyDictionary<FfcSafePrimeGroup, DHParameters> Groups =
        new Dictionary<FfcSafePrimeGroup, DHParameters>
        {
            [FfcSafePrimeGroup.Modp2048] = DHStandardGroups.rfc3526_2048,
            [FfcSafePrimeGroup.Modp3072] = DHStandardGroups.rfc3526_3072,
            [FfcSafePrimeGroup.Modp4096] = DHStandardGroups.rfc3526_4096,
            [FfcSafePrimeGroup.Modp6144] = DHStandardGroups.rfc3526_6144,
            [FfcSafePrimeGroup.Modp8192] = DHStandardGroups.rfc3526_8192,
            [FfcSafePrimeGroup.Ffdhe2048] = DHStandardGroups.rfc7919_ffdhe2048,
            [FfcSafePrimeGroup.Ffdhe3072] = DHStandardGroups.rfc7919_ffdhe3072,
            [FfcSafePrimeGroup.Ffdhe4096] = DHStandardGroups.rfc7919_ffdhe4096,
            [FfcSafePrimeGroup.Ffdhe6144] = DHStandardGroups.rfc7919_ffdhe6144,
            [FfcSafePrimeGroup.Ffdhe8192] = DHStandardGroups.rfc7919_ffdhe8192
        };

    private FfcDomain(FfcSafePrimeGroup? group, DHParameters parameters, FfcDomainAssurance? assurance)
    {
        Group = group;
        Parameters = parameters;
        Assurance = assurance;
    }

    public FfcSafePrimeGroup? Group { get; }
    public bool IsNamedSafePrimeGroup => Group.HasValue;
    public FfcDomainAssurance? Assurance { get; }
    internal DHParameters Parameters { get; }
    public int ModulusBits => Parameters.P.BitLength;

    public static FfcDomain Named(FfcSafePrimeGroup group) =>
        Groups.TryGetValue(group, out var parameters)
            ? new FfcDomain(group, parameters, null)
            : throw new ArgumentOutOfRangeException(nameof(group));

    public static FfcDomain ImportFips186(
        ReadOnlySpan<byte> p,
        ReadOnlySpan<byte> q,
        ReadOnlySpan<byte> g,
        FfcDomainAssurance assurance)
    {
        ArgumentNullException.ThrowIfNull(assurance);
        if (p.IsEmpty || q.IsEmpty || g.IsEmpty)
            throw new ArgumentException("FFC domain parameters must be non-empty.");

        var pValue = new BigInteger(1, p.ToArray());
        var qValue = new BigInteger(1, q.ToArray());
        var gValue = new BigInteger(1, g.ToArray());
        if (pValue.BitLength != 2048 || qValue.BitLength is not (224 or 256))
            throw new ArgumentException("FIPS 186-type parameters must use the FB or FC size set.");
        if (!pValue.IsProbablePrime(100) || !qValue.IsProbablePrime(100))
            throw new ArgumentException("FFC p and q must be prime.");
        if (!pValue.Subtract(BigInteger.One).Mod(qValue).Equals(BigInteger.Zero))
            throw new ArgumentException("FFC q must divide p - 1.");
        if (gValue.CompareTo(BigInteger.Two) < 0 || gValue.CompareTo(pValue.Subtract(BigInteger.Two)) > 0 ||
            !gValue.ModPow(qValue, pValue).Equals(BigInteger.One))
            throw new ArgumentException("FFC g must generate the subgroup of order q.");

        return new FfcDomain(null, new DHParameters(pValue, gValue, qValue), assurance);
    }

    internal void ValidatePrivate(BigInteger x)
    {
        var q = Parameters.Q ?? Parameters.P.Subtract(BigInteger.One).ShiftRight(1);
        if (x.CompareTo(BigInteger.One) < 0 || x.CompareTo(q) >= 0)
            throw new ArgumentOutOfRangeException(nameof(x), "FFC private key must be in [1, q - 1].");
    }

    internal void ValidatePublic(BigInteger y)
    {
        var p = Parameters.P;
        var q = Parameters.Q ?? p.Subtract(BigInteger.One).ShiftRight(1);
        if (y.CompareTo(BigInteger.Two) < 0 || y.CompareTo(p.Subtract(BigInteger.Two)) > 0)
            throw new ArgumentOutOfRangeException(nameof(y), "FFC public key is outside [2, p - 2].");
        if (!y.ModPow(q, p).Equals(BigInteger.One))
            throw new ArgumentException("FFC public key is not in the approved subgroup.", nameof(y));
    }
}

/// <summary>A validated static FFC public key.</summary>
public sealed class FfcStaticPublicKey
{
    internal FfcStaticPublicKey(FfcDomain domain, BigInteger y) { Domain = domain; Value = y; }
    public FfcDomain Domain { get; }
    internal BigInteger Value { get; }
    public byte[] Export() => FfcKeyAgreement.Format(Value, Domain.ModulusBits);
    public static FfcStaticPublicKey Import(FfcDomain domain, ReadOnlySpan<byte> encoded) => new(domain, Validate(domain, encoded));
    private static BigInteger Validate(FfcDomain domain, ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(domain);
        var y = new BigInteger(1, encoded.ToArray());
        domain.ValidatePublic(y);
        return y;
    }
}

/// <summary>A validated ephemeral FFC public key.</summary>
public sealed class FfcEphemeralPublicKey
{
    internal FfcEphemeralPublicKey(FfcDomain domain, BigInteger y) { Domain = domain; Value = y; }
    public FfcDomain Domain { get; }
    internal BigInteger Value { get; }
    public byte[] Export() => FfcKeyAgreement.Format(Value, Domain.ModulusBits);
    public static FfcEphemeralPublicKey Import(FfcDomain domain, ReadOnlySpan<byte> encoded) => new(domain, Validate(domain, encoded));
    private static BigInteger Validate(FfcDomain domain, ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(domain);
        var y = new BigInteger(1, encoded.ToArray());
        domain.ValidatePublic(y);
        return y;
    }
}

/// <summary>A generated or imported static FFC key pair.</summary>
public sealed class FfcStaticKeyPair
{
    private FfcStaticKeyPair(FfcDomain domain, BigInteger x, FfcStaticPublicKey publicKey) { Domain = domain; PrivateValue = x; PublicKey = publicKey; }
    public FfcDomain Domain { get; }
    internal BigInteger PrivateValue { get; }
    public FfcStaticPublicKey PublicKey { get; }
    public static FfcStaticKeyPair Generate(FfcDomain domain, SecureRandom? random = null)
    {
        var x = FfcKeyAgreement.GeneratePrivate(domain, random);
        return FromPrivate(domain, x.ToByteArrayUnsigned());
    }
    public static FfcStaticKeyPair FromPrivate(FfcDomain domain, ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(domain);
        var x = new BigInteger(1, encoded.ToArray());
        domain.ValidatePrivate(x);
        var y = domain.Parameters.G.ModPow(x, domain.Parameters.P);
        return new FfcStaticKeyPair(domain, x, new FfcStaticPublicKey(domain, y));
    }
}

/// <summary>A generated or imported ephemeral FFC key pair.</summary>
public sealed class FfcEphemeralKeyPair
{
    private FfcEphemeralKeyPair(FfcDomain domain, BigInteger x, FfcEphemeralPublicKey publicKey) { Domain = domain; PrivateValue = x; PublicKey = publicKey; }
    public FfcDomain Domain { get; }
    internal BigInteger PrivateValue { get; }
    public FfcEphemeralPublicKey PublicKey { get; }
    public static FfcEphemeralKeyPair Generate(FfcDomain domain, SecureRandom? random = null)
    {
        var x = FfcKeyAgreement.GeneratePrivate(domain, random);
        return FromPrivate(domain, x.ToByteArrayUnsigned());
    }
    public static FfcEphemeralKeyPair FromPrivate(FfcDomain domain, ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(domain);
        var x = new BigInteger(1, encoded.ToArray());
        domain.ValidatePrivate(x);
        var y = domain.Parameters.G.ModPow(x, domain.Parameters.P);
        return new FfcEphemeralKeyPair(domain, x, new FfcEphemeralPublicKey(domain, y));
    }
}

/// <summary>SP 800-56A Rev. 3 FFC DH and MQV primitives.</summary>
public static class FfcKeyAgreement
{
    public static byte[] DiffieHellman(FfcStaticKeyPair local, FfcStaticPublicKey remote) =>
        ComputeDh(local.Domain, local.PrivateValue, remote.Domain, remote.Value);

    public static byte[] DiffieHellman(FfcEphemeralKeyPair local, FfcEphemeralPublicKey remote) =>
        ComputeDh(local.Domain, local.PrivateValue, remote.Domain, remote.Value);

    public static byte[] DiffieHellman(FfcEphemeralKeyPair local, FfcStaticPublicKey remote) =>
        ComputeDh(local.Domain, local.PrivateValue, remote.Domain, remote.Value);

    public static byte[] DiffieHellman(FfcStaticKeyPair local, FfcEphemeralPublicKey remote) =>
        ComputeDh(local.Domain, local.PrivateValue, remote.Domain, remote.Value);

    public static byte[] Mqv(
        FfcStaticKeyPair localStatic,
        FfcEphemeralKeyPair localEphemeral,
        FfcStaticPublicKey remoteStatic,
        FfcEphemeralPublicKey remoteEphemeral) =>
        ComputeMqv(localStatic, localEphemeral.PrivateValue, localEphemeral.PublicKey.Value,
            remoteStatic, remoteEphemeral.Domain, remoteEphemeral.Value);

    public static byte[] Mqv1AsPartyU(
        FfcStaticKeyPair localStatic,
        FfcEphemeralKeyPair localEphemeral,
        FfcStaticPublicKey remoteStatic) =>
        ComputeMqv(localStatic, localEphemeral.PrivateValue, localEphemeral.PublicKey.Value,
            remoteStatic, remoteStatic.Domain, remoteStatic.Value);

    public static byte[] Mqv1AsPartyV(
        FfcStaticKeyPair localStatic,
        FfcStaticPublicKey remoteStatic,
        FfcEphemeralPublicKey remoteEphemeral) =>
        ComputeMqv(localStatic, localStatic.PrivateValue, localStatic.PublicKey.Value,
            remoteStatic, remoteEphemeral.Domain, remoteEphemeral.Value);

    private static byte[] ComputeMqv(
        FfcStaticKeyPair localStatic,
        BigInteger localSecondPrivate,
        BigInteger localSecondPublic,
        FfcStaticPublicKey remoteStatic,
        FfcDomain remoteSecondDomain,
        BigInteger remoteSecondPublic)
    {
        EnsureSameDomain(localStatic.Domain, remoteStatic.Domain, remoteSecondDomain);
        var parameters = localStatic.Domain.Parameters;
        var q = parameters.Q ?? parameters.P.Subtract(BigInteger.One).ShiftRight(1);
        int w = (q.BitLength + 1) / 2;
        var twoPowW = BigInteger.One.ShiftLeft(w);
        var localAssociate = localSecondPublic.Mod(twoPowW).Add(twoPowW);
        var remoteAssociate = remoteSecondPublic.Mod(twoPowW).Add(twoPowW);
        var localExponent = localSecondPrivate
            .Add(localAssociate.Multiply(localStatic.PrivateValue))
            .Mod(q);
        var baseValue = remoteSecondPublic
            .Multiply(remoteStatic.Value.ModPow(remoteAssociate, parameters.P))
            .Mod(parameters.P);
        var z = baseValue.ModPow(localExponent, parameters.P);
        if (z.CompareTo(BigInteger.One) <= 0 || z.Equals(parameters.P.Subtract(BigInteger.One)))
            throw new InvalidOperationException("FFC MQV produced an invalid shared secret.");
        return Format(z, localStatic.Domain.ModulusBits);
    }

    internal static BigInteger GeneratePrivate(FfcDomain domain, SecureRandom? random)
    {
        ArgumentNullException.ThrowIfNull(domain);
        var q = domain.Parameters.Q ?? domain.Parameters.P.Subtract(BigInteger.One).ShiftRight(1);
        return BigIntegers.CreateRandomInRange(BigInteger.One, q.Subtract(BigInteger.One), random ?? new SecureRandom());
    }

    internal static byte[] Format(BigInteger value, int modulusBits)
    {
        var raw = value.ToByteArrayUnsigned();
        int length = (modulusBits + 7) / 8;
        if (raw.Length == length)
            return raw;
        var output = new byte[length];
        Buffer.BlockCopy(raw, 0, output, length - raw.Length, raw.Length);
        return output;
    }

    private static byte[] ComputeDh(FfcDomain localDomain, BigInteger privateValue, FfcDomain remoteDomain, BigInteger publicValue)
    {
        EnsureSameDomain(localDomain, remoteDomain);
        remoteDomain.ValidatePublic(publicValue);
        var z = publicValue.ModPow(privateValue, localDomain.Parameters.P);
        if (z.Equals(BigInteger.One))
            throw new InvalidOperationException("FFC DH produced the invalid shared secret 1.");
        return Format(z, localDomain.ModulusBits);
    }

    private static void EnsureSameDomain(params FfcDomain[] domains)
    {
        if (domains.Length < 2)
            return;
        var first = domains[0].Parameters;
        for (int i = 1; i < domains.Length; i++)
        {
            var candidate = domains[i].Parameters;
            if (!candidate.P.Equals(first.P) || !Equals(candidate.Q, first.Q) || !candidate.G.Equals(first.G))
                throw new ArgumentException("FFC keys must use the same domain parameters.");
        }
    }
}
