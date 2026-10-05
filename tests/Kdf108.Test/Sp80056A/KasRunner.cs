using System;
using System.Collections.Concurrent;
using System.IO;

namespace Kdf108.Test.Nist80056A;

/// <summary>A production key import failed with the given failure for the given party and role.</summary>
internal sealed class KeyRejectedException(string party, string role, InvalidKeyException inner)
    : Exception($"{party} {role} key rejected: {inner.Failure}", inner)
{
    internal string Party { get; } = party;
    internal string Role { get; } = role;
    internal KeyFailure Failure { get; } = inner.Failure;
}

/// <summary>Computes Z for a KAS vector using only the public scheme APIs.</summary>
internal static class KasRunner
{
    private static readonly ConcurrentDictionary<string, FfcDomain> FfcDomains = new(StringComparer.Ordinal);

    internal static byte[] ComputeZ(KasVector v) => v.Family == KasFamily.Ecc ? Ecc(v) : Ffc(v);

    internal static EcDomain Domain(KasVector v) => EcDomain.Named(v.Curve switch
    {
        "P-224" => EcCurve.P224, "P-256" => EcCurve.P256, "P-384" => EcCurve.P384, "P-521" => EcCurve.P521,
        "K-233" => EcCurve.K233, "K-283" => EcCurve.K283, "K-409" => EcCurve.K409, "K-571" => EcCurve.K571,
        "B-233" => EcCurve.B233, "B-283" => EcCurve.B283, "B-409" => EcCurve.B409, "B-571" => EcCurve.B571,
        _ => throw new InvalidDataException($"Unknown curve '{v.Curve}'.")
    });

    private static byte[] Ecc(KasVector v)
    {
        EcDomain d = Domain(v);

        EcStaticKeyPair IutS() => Import("IUT", "static", () => EcStaticKeyPair.Import(d, v.Hex("dsIUT"), Point(d, v, "QsIUT")));
        EcEphemeralKeyPair IutE() => Import("IUT", "ephemeral", () => EcEphemeralKeyPair.Import(d, v.Hex("deIUT"), Point(d, v, "QeIUT")));
        EcStaticPublicKey CavsS() => Import("CAVS", "static", () => EcStaticPublicKey.Import(d, Point(d, v, "QsCAVS")));
        EcEphemeralPublicKey CavsE() => Import("CAVS", "ephemeral", () => EcEphemeralPublicKey.Import(d, Point(d, v, "QeCAVS")));
        bool u = v.IutIsInitiator;

        return v.Scheme.Replace(" ", "") switch
        {
            "ECCEphemeralUnifiedScheme" => EcSchemes.Ephemeral(IutE(), CavsE()),
            "ECCStaticUnifiedScheme" => EcSchemes.Static(IutS(), CavsS()),
            "ECCFullUnifiedScheme" => EcSchemes.Hybrid(IutS(), IutE(), CavsS(), CavsE()),
            "ECCOnePassUnifiedScheme" => u ? EcSchemes.HybridOneFlowAsPartyU(IutS(), IutE(), CavsS()) : EcSchemes.HybridOneFlowAsPartyV(IutS(), CavsS(), CavsE()),
            // The no-key-confirmation directory is misnamed "OnePassDH Unified"; its contents are dhOnePassDH.
            "ECCOnePassDHScheme" or "ECCOnePassDHUnifiedScheme" => u ? EcSchemes.OneFlowAsPartyU(IutE(), CavsS()) : EcSchemes.OneFlowAsPartyV(IutS(), CavsE()),
            "ECCFullMQVScheme" => EcSchemes.Mqv2(IutS(), IutE(), CavsS(), CavsE()),
            "ECCOnePassMQVScheme" => u ? EcSchemes.Mqv1AsPartyU(IutS(), IutE(), CavsS()) : EcSchemes.Mqv1AsPartyV(IutS(), CavsS(), CavsE()),
            _ => throw new InvalidDataException($"Unknown ECC scheme '{v.Scheme}'.")
        };
    }

    private static byte[] Ffc(KasVector v)
    {
        string p = v.Record.Header("P")!, q = v.Record.Header("Q")!, g = v.Record.Header("G")!;
        FfcDomain d = FfcDomains.GetOrAdd($"{p}|{q}|{g}", _ => FfcDomain.ImportFips186(
            Convert.FromHexString(p), Convert.FromHexString(q), Convert.FromHexString(g), FfcDomainAssurance.TrustedAuthority("NIST CAVP KAS 2016")));

        FfcStaticKeyPair IutS() => Import("IUT", "static", () => FfcStaticKeyPair.Import(d, v.Hex("XstatIUT"), v.Hex("YstatIUT")));
        FfcEphemeralKeyPair IutE() => Import("IUT", "ephemeral", () => FfcEphemeralKeyPair.Import(d, v.Hex("XephemIUT"), v.Hex("YephemIUT")));
        FfcStaticPublicKey CavsS() => Import("CAVS", "static", () => FfcStaticPublicKey.Import(d, v.Hex("YstatCAVS")));
        FfcEphemeralPublicKey CavsE() => Import("CAVS", "ephemeral", () => FfcEphemeralPublicKey.Import(d, v.Hex("YephemCAVS")));
        bool u = v.IutIsInitiator;

        return v.Scheme.Replace(" ", "") switch
        {
            "FFCEphemeralScheme" => FfcSchemes.Ephemeral(IutE(), CavsE()),
            "FFCStaticScheme" => FfcSchemes.Static(IutS(), CavsS()),
            "FFCOneFlowScheme" => u ? FfcSchemes.OneFlowAsPartyU(IutE(), CavsS()) : FfcSchemes.OneFlowAsPartyV(IutS(), CavsE()),
            "FFCHybrid1Scheme" => FfcSchemes.Hybrid(IutS(), IutE(), CavsS(), CavsE()),
            "FFCHybridOneFlowScheme" or "FFCHybrid1FlowScheme" => u ? FfcSchemes.HybridOneFlowAsPartyU(IutS(), IutE(), CavsS()) : FfcSchemes.HybridOneFlowAsPartyV(IutS(), CavsS(), CavsE()),
            "FFCMQV2Scheme" => FfcSchemes.Mqv2(IutS(), IutE(), CavsS(), CavsE()),
            "FFCMQV1Scheme" => u ? FfcSchemes.Mqv1AsPartyU(IutS(), IutE(), CavsS()) : FfcSchemes.Mqv1AsPartyV(IutS(), CavsS(), CavsE()),
            _ => throw new InvalidDataException($"Unknown FFC scheme '{v.Scheme}'.")
        };
    }

    private static T Import<T>(string party, string role, Func<T> import)
    {
        try { return import(); }
        catch (InvalidKeyException ex) { throw new KeyRejectedException(party, role, ex); }
    }

    /// <summary>
    /// 04 || X || Y with each coordinate at the curve's width. CAVP sometimes pads coordinates with
    /// extra leading zero bytes; anything else is passed through unchanged for production to judge.
    /// </summary>
    internal static byte[] Point(EcDomain d, KasVector v, string name)
    {
        int width = (d.FieldBits + 7) / 8;
        byte[] Coordinate(string suffix)
        {
            byte[] c = v.Hex(name + suffix);
            int excess = c.Length - width;
            if (excess > 0 && Array.TrueForAll(c[..excess], b => b == 0)) return c[excess..];
            if (excess >= 0) return c;
            var padded = new byte[width];
            c.CopyTo(padded, -excess);
            return padded;
        }
        return [0x04, .. Coordinate("x"), .. Coordinate("y")];
    }
}
