using System;
using System.Linq;
using Org.BouncyCastle.Security;

namespace Kdf108.Examples;

/// <summary>
/// Two parties agree on Z with an SP 800-56A scheme, derive keys from it with SP 800-56C, and
/// optionally confirm the keys with SP 800-56A key confirmation. Both parties run in-process.
/// Every library call goes through an injected service, so it is logged by the host's logging.
/// </summary>
public sealed class KeyAgreementWalkthrough(
    IEcKeyAgreement ecc,
    IFfcKeyAgreement ffc,
    ISp80056CKdf kdf56C,
    IKeyConfirmation confirmation,
    SecureRandom random)
{
    /// <summary>The outcome of one run: what each party derived and whether both tags verified.</summary>
    public sealed record Result(int ZBits, byte[] KeyU, byte[] KeyV, bool? TagsVerified);

    private static readonly byte[] PartyUId = "alice@example"u8.ToArray();
    private static readonly byte[] PartyVId = "bob@example"u8.ToArray();

    public Result Run(string family, string scheme, string kdf, bool confirm)
    {
        var (zU, zV, ephemeralU, ephemeralV) = family switch
        {
            "ecc" => Ecc(scheme),
            "ffc" => Ffc(scheme),
            _ => throw new ArgumentException($"Unknown family '{family}'.", nameof(family))
        };

        try
        {
            // FixedInfo binds the keys to the algorithm and both parties. Length-prefix every
            // variable-length field so no two inputs can encode the same bytes.
            byte[] fixedInfo = LengthPrefixed("AES-256-GCM"u8, PartyUId, PartyVId);
            var dkmLength = BitLength.Create(confirm ? 512 : 256); // MacKey || session key when confirming
            byte[] dkmU = Derive(zU, kdf, fixedInfo, dkmLength);
            byte[] dkmV = Derive(zV, kdf, fixedInfo, dkmLength);

            bool? verified = null;
            if (confirm)
            {
                // Each side sends KC_2 for its own role; the other side checks it.
                var mac = KeyConfirmationMac.Hmac(NistHashAlgorithm.Sha256);
                var tagLength = BitLength.Create(128);
                KeyConfirmationContext Context(Party provider) =>
                    new(KeyConfirmationMode.Bilateral, provider, PartyUId, PartyVId, ephemeralU, ephemeralV);
                byte[] tagFromU = confirmation.GenerateTag(dkmU.AsSpan(0, 32), Context(Party.U), mac, tagLength, SecurityStrength.Bits128);
                byte[] tagFromV = confirmation.GenerateTag(dkmV.AsSpan(0, 32), Context(Party.V), mac, tagLength, SecurityStrength.Bits128);
                verified = confirmation.VerifyTag(tagFromU, dkmV.AsSpan(0, 32), Context(Party.U), mac, tagLength, SecurityStrength.Bits128)
                        && confirmation.VerifyTag(tagFromV, dkmU.AsSpan(0, 32), Context(Party.V), mac, tagLength, SecurityStrength.Bits128);
            }

            int offset = confirm ? 32 : 0;
            var result = new Result(zU.Length * 8, dkmU[offset..], dkmV[offset..], verified);
            Array.Clear(dkmU);
            Array.Clear(dkmV);
            return result;
        }
        finally
        {
            Array.Clear(zU);
            Array.Clear(zV);
        }
    }

    private byte[] Derive(byte[] z, string kdf, byte[] fixedInfo, BitLength length) => kdf switch
    {
        "one-step" => kdf56C.OneStep(z, OneStepFunction.HashFunction(NistHashAlgorithm.Sha256), fixedInfo, length, SecurityStrength.Bits128),
        "two-step" => kdf56C.TwoStep(z, Extraction.Hmac(NistHashAlgorithm.Sha256),
            KeyExpansion.Counter(Sp800108.FixedInput("session keys"u8, fixedInfo, length)), length, SecurityStrength.Bits128),
        _ => throw new ArgumentException($"Unknown KDF '{kdf}'.", nameof(kdf))
    };

    private (byte[] ZU, byte[] ZV, byte[] EphemeralU, byte[] EphemeralV) Ecc(string scheme)
    {
        var d = EcDomain.Named(EcCurve.P256);
        var uS = EcStaticKeyPair.Generate(d, random);
        var uE = EcEphemeralKeyPair.Generate(d, random);
        var vS = EcStaticKeyPair.Generate(d, random);
        var vE = EcEphemeralKeyPair.Generate(d, random);
        // Key-confirmation EphemData is the ephemeral public key without the 04 prefix, or empty.
        byte[] E(EcPublicKey key) => key.Export()[1..];
        return scheme switch
        {
            "ephemeral" => (ecc.Ephemeral(uE, vE.PublicKey), ecc.Ephemeral(vE, uE.PublicKey), E(uE.PublicKey), E(vE.PublicKey)),
            "static" => (ecc.Static(uS, vS.PublicKey), ecc.Static(vS, uS.PublicKey), [], []),
            "one-flow" => (ecc.OneFlowAsPartyU(uE, vS.PublicKey), ecc.OneFlowAsPartyV(vS, uE.PublicKey), E(uE.PublicKey), []),
            "hybrid" => (ecc.Hybrid(uS, uE, vS.PublicKey, vE.PublicKey), ecc.Hybrid(vS, vE, uS.PublicKey, uE.PublicKey), E(uE.PublicKey), E(vE.PublicKey)),
            "hybrid-one-flow" => (ecc.HybridOneFlowAsPartyU(uS, uE, vS.PublicKey), ecc.HybridOneFlowAsPartyV(vS, uS.PublicKey, uE.PublicKey), E(uE.PublicKey), []),
            "mqv2" => (ecc.Mqv2(uS, uE, vS.PublicKey, vE.PublicKey), ecc.Mqv2(vS, vE, uS.PublicKey, uE.PublicKey), E(uE.PublicKey), E(vE.PublicKey)),
            "mqv1" => (ecc.Mqv1AsPartyU(uS, uE, vS.PublicKey), ecc.Mqv1AsPartyV(vS, uS.PublicKey, uE.PublicKey), E(uE.PublicKey), []),
            _ => throw new ArgumentException($"Unknown scheme '{scheme}'.", nameof(scheme))
        };
    }

    private (byte[] ZU, byte[] ZV, byte[] EphemeralU, byte[] EphemeralV) Ffc(string scheme)
    {
        var d = FfcDomain.Named(FfcSafePrimeGroup.Ffdhe2048);
        var uS = FfcStaticKeyPair.Generate(d, random);
        var uE = FfcEphemeralKeyPair.Generate(d, random);
        var vS = FfcStaticKeyPair.Generate(d, random);
        var vE = FfcEphemeralKeyPair.Generate(d, random);
        byte[] E(FfcPublicKey key) => key.Export();
        return scheme switch
        {
            "ephemeral" => (ffc.Ephemeral(uE, vE.PublicKey), ffc.Ephemeral(vE, uE.PublicKey), E(uE.PublicKey), E(vE.PublicKey)),
            "static" => (ffc.Static(uS, vS.PublicKey), ffc.Static(vS, uS.PublicKey), [], []),
            "one-flow" => (ffc.OneFlowAsPartyU(uE, vS.PublicKey), ffc.OneFlowAsPartyV(vS, uE.PublicKey), E(uE.PublicKey), []),
            "hybrid" => (ffc.Hybrid(uS, uE, vS.PublicKey, vE.PublicKey), ffc.Hybrid(vS, vE, uS.PublicKey, uE.PublicKey), E(uE.PublicKey), E(vE.PublicKey)),
            "hybrid-one-flow" => (ffc.HybridOneFlowAsPartyU(uS, uE, vS.PublicKey), ffc.HybridOneFlowAsPartyV(vS, uS.PublicKey, uE.PublicKey), E(uE.PublicKey), []),
            "mqv2" => (ffc.Mqv2(uS, uE, vS.PublicKey, vE.PublicKey), ffc.Mqv2(vS, vE, uS.PublicKey, uE.PublicKey), E(uE.PublicKey), E(vE.PublicKey)),
            "mqv1" => (ffc.Mqv1AsPartyU(uS, uE, vS.PublicKey), ffc.Mqv1AsPartyV(vS, uS.PublicKey, uE.PublicKey), E(uE.PublicKey), []),
            _ => throw new ArgumentException($"Unknown scheme '{scheme}'.", nameof(scheme))
        };
    }

    /// <summary>Each field as a 4-byte big-endian length followed by its bytes.</summary>
    internal static byte[] LengthPrefixed(params byte[][] fields)
    {
        var output = new byte[fields.Sum(f => 4 + f.Length)];
        int offset = 0;
        foreach (byte[] field in fields)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(offset), field.Length);
            field.CopyTo(output, offset + 4);
            offset += 4 + field.Length;
        }
        return output;
    }

    private static byte[] LengthPrefixed(ReadOnlySpan<byte> algorithm, byte[] u, byte[] v) => LengthPrefixed(algorithm.ToArray(), u, v);

}
