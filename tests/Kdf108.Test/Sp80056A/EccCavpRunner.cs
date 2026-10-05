// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Sp80056A;

namespace Kdf108.Test.Sp80056A;

/// <summary>Runs ECC CAVP vectors exclusively through the public domain model.</summary>
internal static class EccCavpRunner
{
    internal static byte[] ComputeZ(CavpTestVector vector)
    {
        ArgumentNullException.ThrowIfNull(vector);
        string curve = vector.Curve ?? throw Missing(vector, "curve");

        using SharedSecret secret = vector.Source.Scheme switch
        {
            "ECC Ephemeral Unified Scheme" => EcdhKeyAgreement.ComputeEphemeralUnified(
                Pair(vector.DeIUT, vector.QeIUTx, vector.QeIUTy, curve, vector, "IUT ephemeral"),
                Public(vector.QeCAVSx, vector.QeCAVSy, curve, vector, "CAVS ephemeral")),

            "ECC Static Unified Scheme" or "ECC StaticUnified Scheme" => EcdhKeyAgreement.ComputeStaticUnified(
                Pair(vector.DsIUT, vector.QsIUTx, vector.QsIUTy, curve, vector, "IUT static"),
                Public(vector.QsCAVSx, vector.QsCAVSy, curve, vector, "CAVS static")),

            "ECC Full Unified Scheme" or "ECC FullUnified Scheme" => EcdhKeyAgreement.ComputeFullUnified(
                Pair(vector.DsIUT, vector.QsIUTx, vector.QsIUTy, curve, vector, "IUT static"),
                Pair(vector.DeIUT, vector.QeIUTx, vector.QeIUTy, curve, vector, "IUT ephemeral"),
                Public(vector.QsCAVSx, vector.QsCAVSy, curve, vector, "CAVS static"),
                Public(vector.QeCAVSx, vector.QeCAVSy, curve, vector, "CAVS ephemeral")),

            "ECC One Pass Unified Scheme" or "ECC OnePass Unified Scheme" => OnePassUnified(vector, curve),
            // The no-key-confirmation corpus uses an inconsistent directory name,
            // but its header and key fields identify the primitive as dhOnePassDH.
            "ECC One Pass DH Scheme" or "ECC OnePassDH Unified Scheme" => OnePassDh(vector, curve),

            "ECC Full MQV Scheme" => EcMqvKeyAgreement.ComputeFullMqv(
                Pair(vector.DsIUT, vector.QsIUTx, vector.QsIUTy, curve, vector, "IUT static"),
                Pair(vector.DeIUT, vector.QeIUTx, vector.QeIUTy, curve, vector, "IUT ephemeral"),
                Public(vector.QsCAVSx, vector.QsCAVSy, curve, vector, "CAVS static"),
                Public(vector.QeCAVSx, vector.QeCAVSy, curve, vector, "CAVS ephemeral")),

            "ECC One Pass MQV Scheme" or "ECC OnePass MQV Scheme" => OnePassMqv(vector, curve),
            _ => throw new NotSupportedException($"Unsupported ECC CAVP scheme '{vector.Source.Scheme}'.")
        };

        return secret.ToArray();
    }

    private static SharedSecret OnePassDh(CavpTestVector vector, string curve) =>
        vector.Source.Role switch
        {
            "initiator" => EcdhKeyAgreement.ComputeOnePassDH(
                Pair(vector.DeIUT, vector.QeIUTx, vector.QeIUTy, curve, vector, "IUT ephemeral"),
                Public(vector.QsCAVSx, vector.QsCAVSy, curve, vector, "CAVS static")),
            "responder" => EcdhKeyAgreement.ComputeOnePassDH(
                Pair(vector.DsIUT, vector.QsIUTx, vector.QsIUTy, curve, vector, "IUT static"),
                Public(vector.QeCAVSx, vector.QeCAVSy, curve, vector, "CAVS ephemeral")),
            _ => throw Missing(vector, "party role")
        };

    private static SharedSecret OnePassUnified(CavpTestVector vector, string curve) =>
        vector.Source.Role switch
        {
            "initiator" => EcdhKeyAgreement.ComputeOnePassUnifiedAsInitiator(
                Pair(vector.DsIUT, vector.QsIUTx, vector.QsIUTy, curve, vector, "IUT static"),
                Pair(vector.DeIUT, vector.QeIUTx, vector.QeIUTy, curve, vector, "IUT ephemeral"),
                Public(vector.QsCAVSx, vector.QsCAVSy, curve, vector, "CAVS static")),
            "responder" => EcdhKeyAgreement.ComputeOnePassUnifiedAsResponder(
                Pair(vector.DsIUT, vector.QsIUTx, vector.QsIUTy, curve, vector, "IUT static"),
                Public(vector.QsCAVSx, vector.QsCAVSy, curve, vector, "CAVS static"),
                Public(vector.QeCAVSx, vector.QeCAVSy, curve, vector, "CAVS ephemeral")),
            _ => throw Missing(vector, "party role")
        };

    private static SharedSecret OnePassMqv(CavpTestVector vector, string curve)
    {
        EcKeyPair localStatic = Pair(vector.DsIUT, vector.QsIUTx, vector.QsIUTy, curve, vector, "IUT static");
        EcPublicKey remoteStatic = Public(vector.QsCAVSx, vector.QsCAVSy, curve, vector, "CAVS static");
        return vector.Source.Role switch
        {
            // In one-pass MQV the initiator supplies its ephemeral key while the responder's
            // static key occupies both remote MQV inputs.
            "initiator" => EcMqvKeyAgreement.ComputeFullMqv(
                localStatic,
                Pair(vector.DeIUT, vector.QeIUTx, vector.QeIUTy, curve, vector, "IUT ephemeral"),
                remoteStatic,
                remoteStatic),
            "responder" => EcMqvKeyAgreement.ComputeOnePassMqv(
                localStatic,
                remoteStatic,
                Public(vector.QeCAVSx, vector.QeCAVSy, curve, vector, "CAVS ephemeral")),
            _ => throw Missing(vector, "party role")
        };
    }

    private static EcKeyPair Pair(
        byte[]? d, byte[]? x, byte[]? y, string curve, CavpTestVector vector, string name) =>
        EcKeyPair.Create(
            d ?? throw Missing(vector, $"{name} private key"),
            EncodePoint(x, y, curve, vector, name),
            curve);

    private static EcPublicKey Public(
        byte[]? x, byte[]? y, string curve, CavpTestVector vector, string name) =>
        new(EncodePoint(x, y, curve, vector, name), curve);

    private static byte[] EncodePoint(
        byte[]? x, byte[]? y, string curve, CavpTestVector vector, string name)
    {
        if (x is null) throw Missing(vector, $"{name} X coordinate");
        if (y is null) throw Missing(vector, $"{name} Y coordinate");
        int coordinateLength = curve switch
        {
            "P-224" => 28, "P-256" => 32, "P-384" => 48, "P-521" => 66,
            "B-233" or "K-233" => 30, "B-283" or "K-283" => 36,
            "B-409" or "K-409" => 52, "B-571" or "K-571" => 72,
            _ => throw new NotSupportedException($"Unsupported ECC CAVP curve '{curve}'.")
        };
        x = NormalizeCoordinate(x, coordinateLength, curve, name);
        y = NormalizeCoordinate(y, coordinateLength, curve, name);

        var encoded = new byte[1 + (2 * coordinateLength)];
        encoded[0] = 0x04;
        x.CopyTo(encoded, 1 + coordinateLength - x.Length);
        y.CopyTo(encoded, 1 + (2 * coordinateLength) - y.Length);
        return encoded;
    }

    private static byte[] NormalizeCoordinate(byte[] coordinate, int length, string curve, string name)
    {
        int excess = coordinate.Length - length;
        if (excess <= 0) return coordinate;
        for (int i = 0; i < excess; i++)
        {
            if (coordinate[i] != 0)
                throw new ArgumentException($"{name} coordinate exceeds the {curve} field width.");
        }
        return coordinate[excess..];
    }

    private static InvalidOperationException Missing(CavpTestVector vector, string field) =>
        new($"ECC vector {vector.Count} from '{vector.Source.FilePath}' is missing {field}.");
}
