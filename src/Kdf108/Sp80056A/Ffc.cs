// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using Kdf108.Internal;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Kdf108;

/// <summary>Named safe-prime groups approved by SP 800-56A Rev. 3 Appendix D.</summary>
public enum FfcSafePrimeGroup
{
    /// <summary>MODP-2048 (RFC 3526).</summary>
    Modp2048,
    /// <summary>MODP-3072 (RFC 3526).</summary>
    Modp3072,
    /// <summary>MODP-4096 (RFC 3526).</summary>
    Modp4096,
    /// <summary>MODP-6144 (RFC 3526).</summary>
    Modp6144,
    /// <summary>MODP-8192 (RFC 3526).</summary>
    Modp8192,
    /// <summary>ffdhe2048 (RFC 7919).</summary>
    Ffdhe2048,
    /// <summary>ffdhe3072 (RFC 7919).</summary>
    Ffdhe3072,
    /// <summary>ffdhe4096 (RFC 7919).</summary>
    Ffdhe4096,
    /// <summary>ffdhe6144 (RFC 7919).</summary>
    Ffdhe6144,
    /// <summary>ffdhe8192 (RFC 7919).</summary>
    Ffdhe8192
}

/// <summary>How assurance of FIPS 186-type domain-parameter validity was obtained (SP 800-56A Rev. 3 §5.5.2).</summary>
public sealed class FfcDomainAssurance
{
    private readonly byte[]? _seed;

    private FfcDomainAssurance(string? authority, byte[]? seed, int counter, NistHashAlgorithm hash)
    {
        Authority = authority;
        _seed = seed;
        Counter = counter;
        Hash = hash;
    }

    /// <summary>The trusted party that vouched for the parameters, or <see langword="null"/> when the generation evidence is replayed.</summary>
    public string? Authority { get; }

    /// <summary>The FIPS 186-4 A.1.1.2 counter (evidence only).</summary>
    public int Counter { get; }

    /// <summary>The FIPS 186-4 generation hash (evidence only).</summary>
    public NistHashAlgorithm Hash { get; }

    internal ReadOnlySpan<byte> Seed => _seed;
    internal bool HasEvidence => _seed is not null;

    /// <summary>
    /// Validate the parameters by replaying FIPS 186-4 Appendix A.1.1.3 probable-prime generation
    /// from its seed, counter, and hash, and by testing p and q for primality.
    /// </summary>
    public static FfcDomainAssurance Fips186Evidence(ReadOnlySpan<byte> seed, int counter, NistHashAlgorithm hash)
    {
        if (seed.IsEmpty) throw new InvalidKeyException(KeyFailure.InvalidDomain, "FIPS 186 evidence requires the generation seed.");
        if (counter < 0) throw new InvalidKeyException(KeyFailure.InvalidDomain, "The FIPS 186 counter must not be negative.");
        if (hash is not (NistHashAlgorithm.Sha224 or NistHashAlgorithm.Sha256 or NistHashAlgorithm.Sha384 or NistHashAlgorithm.Sha512))
            throw new InvalidKeyException(KeyFailure.InvalidDomain, "FIPS 186-4 generation uses SHA-224, SHA-256, SHA-384, or SHA-512.");
        return new FfcDomainAssurance(null, seed.ToArray(), counter, hash);
    }

    /// <summary>
    /// Assurance obtained from a trusted party (SP 800-56A §5.5.2). Only the structural checks run:
    /// sizes, q | p - 1, and g of order q. Primality is taken from the trusted party.
    /// </summary>
    public static FfcDomainAssurance TrustedAuthority(string authority) =>
        string.IsNullOrWhiteSpace(authority)
            ? throw new InvalidKeyException(KeyFailure.InvalidDomain, "Name the trusted authority.")
            : new FfcDomainAssurance(authority, null, 0, default);
}

/// <summary>Validated finite-field domain parameters: a named safe-prime group or FIPS 186-type parameters.</summary>
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

    private FfcDomain(FfcSafePrimeGroup? group, BigInteger p, BigInteger q, BigInteger g, FfcDomainAssurance? assurance)
    {
        Group = group;
        P = p;
        Q = q;
        G = g;
        Assurance = assurance;
    }

    /// <summary>The named group, or <see langword="null"/> for FIPS 186-type parameters.</summary>
    public FfcSafePrimeGroup? Group { get; }

    /// <summary>How validity was established for FIPS 186-type parameters.</summary>
    public FfcDomainAssurance? Assurance { get; }

    /// <summary>The bit length of p, which is also the bit length of Z.</summary>
    public int ModulusBits => P.BitLength;

    internal BigInteger P { get; }
    internal BigInteger Q { get; }
    internal BigInteger G { get; }
    internal int ModulusBytes => (P.BitLength + 7) / 8;

    /// <summary>A named safe-prime group (q = (p - 1) / 2).</summary>
    public static FfcDomain Named(FfcSafePrimeGroup group) =>
        Groups.TryGetValue(group, out DHParameters? parameters)
            ? new FfcDomain(group, parameters.P, parameters.Q ?? parameters.P.ShiftRight(1), parameters.G, null)
            : throw new InvalidKeyException(KeyFailure.InvalidDomain, $"Unknown safe-prime group {group}.");

    /// <summary>Imports and validates FIPS 186-type parameters from the FB (2048/224) or FC (2048/256) size set.</summary>
    public static FfcDomain ImportFips186(ReadOnlySpan<byte> p, ReadOnlySpan<byte> q, ReadOnlySpan<byte> g, FfcDomainAssurance assurance)
    {
        ArgumentNullException.ThrowIfNull(assurance);
        var pValue = new BigInteger(1, p);
        var qValue = new BigInteger(1, q);
        var gValue = new BigInteger(1, g);
        if (pValue.BitLength != 2048 || qValue.BitLength is not (224 or 256))
            throw new InvalidKeyException(KeyFailure.InvalidDomain, "FIPS 186-type parameters must use the FB (2048/224) or FC (2048/256) size set.");
        if (assurance.HasEvidence)
        {
            if (!qValue.IsProbablePrime(100))
                throw new InvalidKeyException(KeyFailure.InvalidDomain, "FFC q is not prime.");
            Fips186.ReplayProbablePrimeGeneration(pValue, qValue, assurance);
        }
        if (!pValue.Subtract(BigInteger.One).Mod(qValue).Equals(BigInteger.Zero))
            throw new InvalidKeyException(KeyFailure.InvalidDomain, "FFC q must divide p - 1.");
        if (gValue.CompareTo(BigInteger.Two) < 0 || gValue.CompareTo(pValue.Subtract(BigInteger.Two)) > 0 ||
            !gValue.ModPow(qValue, pValue).Equals(BigInteger.One))
            throw new InvalidKeyException(KeyFailure.InvalidDomain, "FFC g must generate the subgroup of order q.");
        return new FfcDomain(null, pValue, qValue, gValue, assurance);
    }

    internal bool SameAs(FfcDomain other) =>
        ReferenceEquals(this, other) || (P.Equals(other.P) && Q.Equals(other.Q) && G.Equals(other.G));

    internal BigInteger ImportPrivate(ReadOnlySpan<byte> encoded)
    {
        var x = new BigInteger(1, encoded);
        if (x.SignValue <= 0 || x.CompareTo(Q) >= 0)
            throw new InvalidKeyException(KeyFailure.InvalidPrivateKey, "An FFC private key must be in [1, q - 1].");
        return x;
    }

    /// <summary>Full public-key validation, SP 800-56A Rev. 3 §5.6.2.3.1: 2 ≤ y ≤ p - 2 and y^q ≡ 1 (mod p).</summary>
    internal BigInteger ImportPublic(ReadOnlySpan<byte> encoded)
    {
        var y = new BigInteger(1, encoded);
        if (y.CompareTo(BigInteger.Two) < 0 || y.CompareTo(P.Subtract(BigInteger.Two)) > 0)
            throw new InvalidKeyException(KeyFailure.InvalidPublicKey, "The FFC public key is outside [2, p - 2].");
        if (!y.ModPow(Q, P).Equals(BigInteger.One))
            throw new InvalidKeyException(KeyFailure.InvalidPublicKey, "The FFC public key is not in the order-q subgroup.");
        return y;
    }

    internal BigInteger GeneratePrivate(SecureRandom? random) =>
        BigIntegers.CreateRandomInRange(BigInteger.One, Q.Subtract(BigInteger.One), random ?? new SecureRandom());

    internal byte[] Encode(BigInteger value) => BigIntegers.AsUnsignedByteArray(ModulusBytes, value);
}

/// <summary>A validated FFC public key. See <see cref="FfcStaticPublicKey"/> and <see cref="FfcEphemeralPublicKey"/>.</summary>
public abstract class FfcPublicKey
{
    private protected FfcPublicKey(FfcDomain domain, BigInteger y)
    {
        Domain = domain;
        Y = y;
    }

    /// <summary>The domain parameters.</summary>
    public FfcDomain Domain { get; }

    internal BigInteger Y { get; }

    /// <summary>The public value y as a big-endian integer the length of p.</summary>
    public byte[] Export() => Domain.Encode(Y);
}

/// <summary>An FFC key pair. See <see cref="FfcStaticKeyPair"/> and <see cref="FfcEphemeralKeyPair"/>.</summary>
public abstract class FfcKeyPair<TPublicKey> where TPublicKey : FfcPublicKey
{
    private protected FfcKeyPair(FfcDomain domain, BigInteger x, TPublicKey publicKey)
    {
        Domain = domain;
        X = x;
        PublicKey = publicKey;
    }

    /// <summary>The domain parameters.</summary>
    public FfcDomain Domain { get; }

    /// <summary>The public half.</summary>
    public TPublicKey PublicKey { get; }

    internal BigInteger X { get; }

    /// <summary>The private value x as a fixed-length big-endian integer. Clear it when done.</summary>
    public byte[] ExportPrivate() => BigIntegers.AsUnsignedByteArray((Domain.Q.BitLength + 7) / 8, X);

    private protected static (BigInteger X, BigInteger Y) PairFromPrivate(FfcDomain domain, ReadOnlySpan<byte> privateKey)
    {
        ArgumentNullException.ThrowIfNull(domain);
        BigInteger x = domain.ImportPrivate(privateKey);
        return (x, domain.G.ModPow(x, domain.P));
    }

    private protected static (BigInteger X, BigInteger Y) PairFromImport(FfcDomain domain, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        (BigInteger x, BigInteger y) = PairFromPrivate(domain, privateKey);
        BigInteger supplied = domain.ImportPublic(publicKey);
        if (!supplied.Equals(y))
            throw new InvalidKeyException(KeyFailure.KeyPairMismatch, "The FFC public key does not match the private key.");
        return (x, y);
    }

    private protected static (BigInteger X, BigInteger Y) PairFromRandom(FfcDomain domain, SecureRandom? random)
    {
        ArgumentNullException.ThrowIfNull(domain);
        BigInteger x = domain.GeneratePrivate(random);
        return (x, domain.G.ModPow(x, domain.P));
    }
}

/// <summary>A static FFC public key, validated on import.</summary>
public sealed class FfcStaticPublicKey : FfcPublicKey
{
    internal FfcStaticPublicKey(FfcDomain domain, BigInteger y) : base(domain, y) { }

    /// <summary>Validates and imports y.</summary>
    public static FfcStaticPublicKey Import(FfcDomain domain, ReadOnlySpan<byte> encoded) =>
        new(domain ?? throw new ArgumentNullException(nameof(domain)), domain.ImportPublic(encoded));
}

/// <summary>An ephemeral FFC public key, validated on import.</summary>
public sealed class FfcEphemeralPublicKey : FfcPublicKey
{
    internal FfcEphemeralPublicKey(FfcDomain domain, BigInteger y) : base(domain, y) { }

    /// <summary>Validates and imports y.</summary>
    public static FfcEphemeralPublicKey Import(FfcDomain domain, ReadOnlySpan<byte> encoded) =>
        new(domain ?? throw new ArgumentNullException(nameof(domain)), domain.ImportPublic(encoded));
}

/// <summary>A static FFC key pair.</summary>
public sealed class FfcStaticKeyPair : FfcKeyPair<FfcStaticPublicKey>
{
    private FfcStaticKeyPair(FfcDomain domain, (BigInteger X, BigInteger Y) key) : base(domain, key.X, new FfcStaticPublicKey(domain, key.Y)) { }

    /// <summary>Generates a key pair.</summary>
    public static FfcStaticKeyPair Generate(FfcDomain domain, SecureRandom? random = null) => new(domain, PairFromRandom(domain, random));

    /// <summary>Imports a private key and computes its public key.</summary>
    public static FfcStaticKeyPair FromPrivate(FfcDomain domain, ReadOnlySpan<byte> privateKey) => new(domain, PairFromPrivate(domain, privateKey));

    /// <summary>Imports both halves and checks that they correspond (pairwise consistency).</summary>
    public static FfcStaticKeyPair Import(FfcDomain domain, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey) =>
        new(domain, PairFromImport(domain, privateKey, publicKey));
}

/// <summary>An ephemeral FFC key pair.</summary>
public sealed class FfcEphemeralKeyPair : FfcKeyPair<FfcEphemeralPublicKey>
{
    private FfcEphemeralKeyPair(FfcDomain domain, (BigInteger X, BigInteger Y) key) : base(domain, key.X, new FfcEphemeralPublicKey(domain, key.Y)) { }

    /// <summary>Generates a key pair.</summary>
    public static FfcEphemeralKeyPair Generate(FfcDomain domain, SecureRandom? random = null) => new(domain, PairFromRandom(domain, random));

    /// <summary>Imports a private key and computes its public key.</summary>
    public static FfcEphemeralKeyPair FromPrivate(FfcDomain domain, ReadOnlySpan<byte> privateKey) => new(domain, PairFromPrivate(domain, privateKey));

    /// <summary>Imports both halves and checks that they correspond (pairwise consistency).</summary>
    public static FfcEphemeralKeyPair Import(FfcDomain domain, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey) =>
        new(domain, PairFromImport(domain, privateKey, publicKey));
}

/// <summary>The SP 800-56A Rev. 3 FFC primitives: FFC DH (§5.7.1.1) and FFC MQV (§5.7.2.1).</summary>
internal static class FfcPrimitives
{
    internal static byte[] Dh(FfcDomain domain, BigInteger x, BigInteger remoteY)
    {
        BigInteger z = remoteY.ModPow(x, domain.P);
        return Encode(domain, z, "FFC DH");
    }

    internal static byte[] Mqv(FfcDomain domain, BigInteger staticX, BigInteger ephemeralX, BigInteger ephemeralY, BigInteger remoteStaticY, BigInteger remoteEphemeralY)
    {
        int halfBits = (domain.Q.BitLength + 1) / 2;
        BigInteger power = BigInteger.One.ShiftLeft(halfBits);
        BigInteger localAssociate = ephemeralY.Mod(power).Add(power);
        BigInteger remoteAssociate = remoteEphemeralY.Mod(power).Add(power);
        BigInteger implicitSignature = ephemeralX.Add(localAssociate.Multiply(staticX)).Mod(domain.Q);
        BigInteger z = remoteEphemeralY.Multiply(remoteStaticY.ModPow(remoteAssociate, domain.P)).Mod(domain.P)
            .ModPow(implicitSignature, domain.P);
        return Encode(domain, z, "FFC MQV");
    }

    private static byte[] Encode(FfcDomain domain, BigInteger z, string primitive)
    {
        if (z.CompareTo(BigInteger.One) <= 0 || z.Equals(domain.P.Subtract(BigInteger.One)))
            throw new KeyAgreementException($"{primitive} produced a forbidden shared secret (0, 1, or p - 1).");
        return domain.Encode(z);
    }
}

/// <summary>FIPS 186-4 Appendix A.1.1.3 validation of probable primes p and q from their generation evidence.</summary>
internal static class Fips186
{
    internal static void ReplayProbablePrimeGeneration(BigInteger p, BigInteger q, FfcDomainAssurance evidence)
    {
        const int l = 2048;
        int nBits = q.BitLength;
        byte[] seed = evidence.Seed.ToArray();
        int seedBits = checked(seed.Length * 8);
        IDigest digest = Hashes.CreateDigest(evidence.Hash);
        int outputBits = digest.GetDigestSize() * 8;

        if (seedBits < nBits)
            Fail("The FIPS 186 seed must be at least N bits.");
        if (outputBits < nBits)
            Fail("The FIPS 186 hash output is shorter than q.");
        if (evidence.Counter >= 4 * l)
            Fail("The FIPS 186 counter exceeds 4L - 1.");

        BigInteger u = HashInteger(digest, seed).Mod(BigInteger.One.ShiftLeft(nBits - 1));
        BigInteger expectedQ = BigInteger.One.ShiftLeft(nBits - 1).Add(u).Add(BigInteger.One).Subtract(u.Mod(BigInteger.Two));
        if (!expectedQ.Equals(q))
            Fail("The FIPS 186 seed and hash do not reproduce q.");

        int n = (l - 1) / outputBits;
        int b = (l - 1) % outputBits;
        int offset = 1;
        BigInteger modulus = BigInteger.One.ShiftLeft(seedBits);
        var seedValue = new BigInteger(1, seed);

        for (int i = 0; i <= evidence.Counter; i++)
        {
            BigInteger w = BigInteger.Zero;
            for (int j = 0; j <= n; j++)
            {
                BigInteger argument = seedValue.Add(BigInteger.ValueOf(offset + j)).Mod(modulus);
                BigInteger v = HashInteger(digest, BigIntegers.AsUnsignedByteArray(seed.Length, argument));
                if (j == n)
                    v = v.Mod(BigInteger.One.ShiftLeft(b));
                w = w.Add(v.ShiftLeft(j * outputBits));
            }

            BigInteger x = w.Add(BigInteger.One.ShiftLeft(l - 1));
            BigInteger candidate = x.Subtract(x.Mod(q.ShiftLeft(1)).Subtract(BigInteger.One));
            if (candidate.CompareTo(BigInteger.One.ShiftLeft(l - 1)) >= 0 && candidate.IsProbablePrime(100))
            {
                if (i == evidence.Counter && candidate.Equals(p))
                    return;
                Fail("The FIPS 186 evidence produces a prime before the supplied counter.");
            }

            offset = checked(offset + n + 1);
        }

        Fail("The FIPS 186 seed, counter, and hash do not reproduce p.");
    }

    private static BigInteger HashInteger(IDigest digest, byte[] input)
    {
        digest.Reset();
        digest.BlockUpdate(input, 0, input.Length);
        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return new BigInteger(1, output);
    }

    private static void Fail(string message) => throw new InvalidKeyException(KeyFailure.InvalidDomain, message);
}
