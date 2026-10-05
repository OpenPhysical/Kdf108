// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Kdf108;

/// <summary>The NIST curves approved for SP 800-56A ECC key agreement.</summary>
public enum EcCurve
{
    /// <summary>P-224.</summary>
    P224,
    /// <summary>P-256.</summary>
    P256,
    /// <summary>P-384.</summary>
    P384,
    /// <summary>P-521.</summary>
    P521,
    /// <summary>K-233.</summary>
    K233,
    /// <summary>K-283.</summary>
    K283,
    /// <summary>K-409.</summary>
    K409,
    /// <summary>K-571.</summary>
    K571,
    /// <summary>B-233.</summary>
    B233,
    /// <summary>B-283.</summary>
    B283,
    /// <summary>B-409.</summary>
    B409,
    /// <summary>B-571.</summary>
    B571
}

/// <summary>The domain parameters of an approved NIST curve. Obtain one with <see cref="Named"/>.</summary>
public sealed class EcDomain
{
    private static readonly IReadOnlyDictionary<EcCurve, EcDomain> Domains = Create();

    private EcDomain(EcCurve curve, string name, X9ECParameters parameters)
    {
        Curve = curve;
        Name = name;
        Parameters = new ECDomainParameters(parameters.Curve, parameters.G, parameters.N, parameters.H, parameters.GetSeed());
        CoordinateBytes = (Parameters.Curve.FieldSize + 7) / 8;
    }

    /// <summary>The curve.</summary>
    public EcCurve Curve { get; }

    /// <summary>The NIST name, for example "P-256".</summary>
    public string Name { get; }

    /// <summary>The field size in bits, which is also the bit length of Z.</summary>
    public int FieldBits => Parameters.Curve.FieldSize;

    internal ECDomainParameters Parameters { get; }
    internal int CoordinateBytes { get; }

    /// <summary>Returns the domain for a NIST curve.</summary>
    public static EcDomain Named(EcCurve curve) =>
        Domains.TryGetValue(curve, out EcDomain? domain)
            ? domain
            : throw new InvalidKeyException(KeyFailure.InvalidDomain, $"Unknown curve {curve}.");

    /// <inheritdoc />
    public override string ToString() => Name;

    /// <summary>
    /// Full public-key validation, SP 800-56A Rev. 3 §5.6.2.3.3. The encoding must be the
    /// uncompressed point <c>04 || X || Y</c> with fixed-length coordinates. Bouncy Castle's
    /// point decoding rejects coordinates outside the field and points not on the curve, and
    /// <see cref="ECPoint.IsValid"/> checks nQ = O (implied when the cofactor is 1).
    /// </summary>
    internal ECPoint ImportPublic(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != 1 + (2 * CoordinateBytes) || encoded[0] != 0x04)
            throw new InvalidKeyException(KeyFailure.InvalidPublicKey,
                $"A {Name} public key must be the {1 + (2 * CoordinateBytes)}-byte uncompressed encoding 04 || X || Y.");
        ECPoint point;
        try
        {
            point = Parameters.Curve.DecodePoint(encoded.ToArray());
        }
        catch (ArgumentException ex)
        {
            throw new InvalidKeyException(KeyFailure.InvalidPublicKey, $"The {Name} public key is not a valid curve point.", ex);
        }

        if (point.IsInfinity || !point.IsValid())
            throw new InvalidKeyException(KeyFailure.InvalidPublicKey, $"The {Name} public key is not in the order-n subgroup.");
        return point.Normalize();
    }

    internal BigInteger ImportPrivate(ReadOnlySpan<byte> encoded)
    {
        var d = new BigInteger(1, encoded);
        if (d.SignValue <= 0 || d.CompareTo(Parameters.N) >= 0)
            throw new InvalidKeyException(KeyFailure.InvalidPrivateKey, $"A {Name} private key must be in [1, n - 1].");
        return d;
    }

    internal BigInteger GeneratePrivate(SecureRandom? random) =>
        BigIntegers.CreateRandomInRange(BigInteger.One, Parameters.N.Subtract(BigInteger.One), random ?? new SecureRandom());

    /// <summary>Q = dG, using a fixed-point comb multiplier that is regular in d.</summary>
    internal ECPoint PublicFromPrivate(BigInteger d) => new FixedPointCombMultiplier().Multiply(Parameters.G, d).Normalize();

    internal byte[] Encode(ECPoint point)
    {
        var encoded = new byte[1 + (2 * CoordinateBytes)];
        encoded[0] = 0x04;
        BigIntegers.AsUnsignedByteArray(point.AffineXCoord.ToBigInteger(), encoded, 1, CoordinateBytes);
        BigIntegers.AsUnsignedByteArray(point.AffineYCoord.ToBigInteger(), encoded, 1 + CoordinateBytes, CoordinateBytes);
        return encoded;
    }

    private static IReadOnlyDictionary<EcCurve, EcDomain> Create()
    {
        var domains = new Dictionary<EcCurve, EcDomain>();
        void Add(EcCurve curve, string nist, string bc) => domains[curve] = new EcDomain(curve, nist, ECNamedCurveTable.GetByName(bc));
        Add(EcCurve.P224, "P-224", "P-224");
        Add(EcCurve.P256, "P-256", "P-256");
        Add(EcCurve.P384, "P-384", "P-384");
        Add(EcCurve.P521, "P-521", "P-521");
        Add(EcCurve.K233, "K-233", "sect233k1");
        Add(EcCurve.K283, "K-283", "sect283k1");
        Add(EcCurve.K409, "K-409", "sect409k1");
        Add(EcCurve.K571, "K-571", "sect571k1");
        Add(EcCurve.B233, "B-233", "sect233r1");
        Add(EcCurve.B283, "B-283", "sect283r1");
        Add(EcCurve.B409, "B-409", "sect409r1");
        Add(EcCurve.B571, "B-571", "sect571r1");
        return domains;
    }
}

/// <summary>A validated ECC public key. See <see cref="EcStaticPublicKey"/> and <see cref="EcEphemeralPublicKey"/>.</summary>
public abstract class EcPublicKey
{
    private protected EcPublicKey(EcDomain domain, ECPoint point)
    {
        Domain = domain;
        Point = point;
    }

    /// <summary>The curve.</summary>
    public EcDomain Domain { get; }

    internal ECPoint Point { get; }

    /// <summary>The uncompressed encoding <c>04 || X || Y</c>.</summary>
    public byte[] Export() => Domain.Encode(Point);
}

/// <summary>An ECC key pair. See <see cref="EcStaticKeyPair"/> and <see cref="EcEphemeralKeyPair"/>.</summary>
public abstract class EcKeyPair<TPublicKey> where TPublicKey : EcPublicKey
{
    private protected EcKeyPair(EcDomain domain, BigInteger d, TPublicKey publicKey)
    {
        Domain = domain;
        D = d;
        PublicKey = publicKey;
    }

    /// <summary>The curve.</summary>
    public EcDomain Domain { get; }

    /// <summary>The public half.</summary>
    public TPublicKey PublicKey { get; }

    internal BigInteger D { get; }

    /// <summary>The private key d as a fixed-length big-endian integer. Clear it when done.</summary>
    public byte[] ExportPrivate() => BigIntegers.AsUnsignedByteArray((Domain.Parameters.N.BitLength + 7) / 8, D);

    private protected static (BigInteger D, ECPoint Q) PairFromPrivate(EcDomain domain, ReadOnlySpan<byte> privateKey)
    {
        ArgumentNullException.ThrowIfNull(domain);
        BigInteger d = domain.ImportPrivate(privateKey);
        return (d, domain.PublicFromPrivate(d));
    }

    private protected static (BigInteger D, ECPoint Q) PairFromImport(EcDomain domain, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        ArgumentNullException.ThrowIfNull(domain);
        BigInteger d = domain.ImportPrivate(privateKey);
        ECPoint supplied = domain.ImportPublic(publicKey);
        ECPoint derived = domain.PublicFromPrivate(d);
        if (!derived.Equals(supplied))
            throw new InvalidKeyException(KeyFailure.KeyPairMismatch, $"The {domain.Name} public key does not match the private key.");
        return (d, derived);
    }

    private protected static (BigInteger D, ECPoint Q) PairFromRandom(EcDomain domain, SecureRandom? random)
    {
        ArgumentNullException.ThrowIfNull(domain);
        BigInteger d = domain.GeneratePrivate(random);
        return (d, domain.PublicFromPrivate(d));
    }
}

/// <summary>A static ECC public key, validated on import.</summary>
public sealed class EcStaticPublicKey : EcPublicKey
{
    internal EcStaticPublicKey(EcDomain domain, ECPoint point) : base(domain, point) { }

    /// <summary>Validates and imports <c>04 || X || Y</c>.</summary>
    public static EcStaticPublicKey Import(EcDomain domain, ReadOnlySpan<byte> encoded) =>
        new(domain ?? throw new ArgumentNullException(nameof(domain)), domain.ImportPublic(encoded));
}

/// <summary>An ephemeral ECC public key, validated on import.</summary>
public sealed class EcEphemeralPublicKey : EcPublicKey
{
    internal EcEphemeralPublicKey(EcDomain domain, ECPoint point) : base(domain, point) { }

    /// <summary>Validates and imports <c>04 || X || Y</c>.</summary>
    public static EcEphemeralPublicKey Import(EcDomain domain, ReadOnlySpan<byte> encoded) =>
        new(domain ?? throw new ArgumentNullException(nameof(domain)), domain.ImportPublic(encoded));
}

/// <summary>A static ECC key pair.</summary>
public sealed class EcStaticKeyPair : EcKeyPair<EcStaticPublicKey>
{
    private EcStaticKeyPair(EcDomain domain, (BigInteger D, ECPoint Q) key) : base(domain, key.D, new EcStaticPublicKey(domain, key.Q)) { }

    /// <summary>Generates a key pair.</summary>
    public static EcStaticKeyPair Generate(EcDomain domain, SecureRandom? random = null) => new(domain, PairFromRandom(domain, random));

    /// <summary>Imports a private key and computes its public key.</summary>
    public static EcStaticKeyPair FromPrivate(EcDomain domain, ReadOnlySpan<byte> privateKey) => new(domain, PairFromPrivate(domain, privateKey));

    /// <summary>Imports both halves and checks that they correspond (pairwise consistency).</summary>
    public static EcStaticKeyPair Import(EcDomain domain, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey) =>
        new(domain, PairFromImport(domain, privateKey, publicKey));
}

/// <summary>An ephemeral ECC key pair.</summary>
public sealed class EcEphemeralKeyPair : EcKeyPair<EcEphemeralPublicKey>
{
    private EcEphemeralKeyPair(EcDomain domain, (BigInteger D, ECPoint Q) key) : base(domain, key.D, new EcEphemeralPublicKey(domain, key.Q)) { }

    /// <summary>Generates a key pair.</summary>
    public static EcEphemeralKeyPair Generate(EcDomain domain, SecureRandom? random = null) => new(domain, PairFromRandom(domain, random));

    /// <summary>Imports a private key and computes its public key.</summary>
    public static EcEphemeralKeyPair FromPrivate(EcDomain domain, ReadOnlySpan<byte> privateKey) => new(domain, PairFromPrivate(domain, privateKey));

    /// <summary>Imports both halves and checks that they correspond (pairwise consistency).</summary>
    public static EcEphemeralKeyPair Import(EcDomain domain, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey) =>
        new(domain, PairFromImport(domain, privateKey, publicKey));
}

/// <summary>The SP 800-56A Rev. 3 ECC primitives: ECC CDH (§5.7.1.2) and ECC MQV (§5.7.2.3).</summary>
internal static class EcPrimitives
{
    internal static byte[] Cdh(EcDomain domain, BigInteger d, ECPoint remote)
    {
        var p = domain.Parameters;
        ECPoint z = remote.Multiply(p.H.Multiply(d).Mod(p.N)).Normalize();
        return XCoordinate(domain, z, "ECC CDH");
    }

    internal static byte[] Mqv(EcDomain domain, BigInteger staticD, BigInteger ephemeralD, ECPoint ephemeralQ, ECPoint remoteStatic, ECPoint remoteEphemeral)
    {
        var p = domain.Parameters;
        int halfBits = (p.N.BitLength + 1) / 2;
        BigInteger implicitSignature = ephemeralD.Add(AssociateValue(ephemeralQ, halfBits).Multiply(staticD)).Mod(p.N);
        ECPoint t = remoteEphemeral.Add(remoteStatic.Multiply(AssociateValue(remoteEphemeral, halfBits)));
        ECPoint z = t.Multiply(p.H.Multiply(implicitSignature).Mod(p.N)).Normalize();
        return XCoordinate(domain, z, "ECC MQV");
    }

    private static BigInteger AssociateValue(ECPoint q, int halfBits)
    {
        BigInteger power = BigInteger.One.ShiftLeft(halfBits);
        return q.Normalize().AffineXCoord.ToBigInteger().Mod(power).Add(power);
    }

    private static byte[] XCoordinate(EcDomain domain, ECPoint z, string primitive)
    {
        if (z.IsInfinity)
            throw new KeyAgreementException($"{primitive} produced the point at infinity.");
        return BigIntegers.AsUnsignedByteArray(domain.CoordinateBytes, z.AffineXCoord.ToBigInteger());
    }
}
