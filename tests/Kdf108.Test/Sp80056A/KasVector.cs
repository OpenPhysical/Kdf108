using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Kdf108.Test.Support;

namespace Kdf108.Test.Nist80056A;

internal enum KasFamily { Ecc, Ffc }
internal enum KasStage { Zz, Kdf, KeyConfirmation }

/// <summary>What the CAVP validity test changed, and therefore what the implementation must do.</summary>
internal enum KasEffect { Correct, KeyRejected, ZChanged, DkmChanged, OiChanged, MacDataChanged, TagChanged }

/// <summary>The key import that must fail for a key-validity vector.</summary>
internal sealed record ExpectedRejection(string Party, string Role, KeyFailure[] Failures);

/// <summary>One SP 800-56A KAS validity vector with the metadata its file and section headers imply.</summary>
internal sealed partial record KasVector(
    RspRecord Record,
    KasFamily Family,
    KasStage Stage,
    string Scheme,
    bool IutIsInitiator,
    string? Curve,
    string Hash,
    string? MacVariant)
{
    internal string Result => Record.Text("Result");
    internal string Description => ResultPattern().Match(Result).Groups[3].Value.Trim();
    internal bool ExpectPass => Result.StartsWith('P');
    internal string? Field(string name) => Record.Fields.GetValueOrDefault(name);
    internal byte[] Hex(string name) => Record.Hex(name);

    internal KasEffect Effect
    {
        get
        {
            if (ExpectPass) return KasEffect.Correct;
            string d = Description;
            if (d.Contains("public key", StringComparison.Ordinal) || d.Contains("private key", StringComparison.Ordinal)) return KasEffect.KeyRejected;
            if (d.StartsWith("Z changed", StringComparison.Ordinal)) return KasEffect.ZChanged;
            if (d.StartsWith("DKM changed", StringComparison.Ordinal)) return KasEffect.DkmChanged;
            if (d.StartsWith("OI changed", StringComparison.Ordinal)) return KasEffect.OiChanged;
            if (d.StartsWith("MACData changed", StringComparison.Ordinal)) return KasEffect.MacDataChanged;
            if (d.StartsWith("Tag changed", StringComparison.Ordinal)) return KasEffect.TagChanged;
            throw new InvalidDataException($"{this}: unknown result '{Result}'.");
        }
    }

    /// <summary>
    /// For key-validity vectors: which party's key of which role must be rejected, and how.
    /// "Fails PKV" means public-key validation; "private key changed" means the supplied pair no
    /// longer corresponds (or the private key left [1, n - 1]).
    /// </summary>
    internal ExpectedRejection? Rejection
    {
        get
        {
            if (Effect != KasEffect.KeyRejected) return null;
            var m = RejectionPattern().Match(Description);
            if (!m.Success) throw new InvalidDataException($"{this}: unrecognized key failure '{Description}'.");
            KeyFailure[] failures = m.Groups[3].Value == "public"
                ? [KeyFailure.InvalidPublicKey]
                : [KeyFailure.KeyPairMismatch, KeyFailure.InvalidPrivateKey];
            return new ExpectedRejection(m.Groups[1].Value, m.Groups[2].Value.ToLowerInvariant(), failures);
        }
    }

    public override string ToString() => $"{Path.GetFileName(Record.File)} [{Curve ?? "FFC"} {Hash} {MacVariant}] COUNT={Record.Fields["COUNT"]}";

    [GeneratedRegex(@"^([PF])\s*\((\d+)\s*-(.*)\)$")]
    private static partial Regex ResultPattern();

    [GeneratedRegex(@"^(CAVS|IUT)'s (Static|Ephemeral) (public|private) key")]
    private static partial Regex RejectionPattern();

    internal static IEnumerable<KasVector> Read(string path)
    {
        string normalized = path.Replace('\\', '/');
        KasFamily family = normalized.Contains("KASTestVectorsECC2016", StringComparison.Ordinal) ? KasFamily.Ecc : KasFamily.Ffc;
        KasStage stage = normalized.Contains("Test of 800-56A excluding KDF", StringComparison.Ordinal) ? KasStage.Zz
            : normalized.Contains("No Key Confirmation", StringComparison.Ordinal) ? KasStage.Kdf
            : KasStage.KeyConfirmation;
        string scheme = Path.GetFileName(Path.GetDirectoryName(path))!;
        string name = Path.GetFileName(path);
        bool initiator = name.Contains("_init", StringComparison.Ordinal)
            ? true
            : name.Contains("_resp", StringComparison.Ordinal) ? false : throw new InvalidDataException($"No role in '{name}'.");

        var curves = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (RspRecord record in RspReader.Read(path))
        {
            string? set = null;
            foreach (string header in record.Headers)
            {
                if (header.Length == 2) set = header;
                else if (header.StartsWith("Curve selected:", StringComparison.Ordinal) && set is not null)
                    curves[set] = header["Curve selected:".Length..].Trim();
            }

            string section = record.LatestHeader(h => h.Contains(" - SHA", StringComparison.Ordinal))
                ?? throw new InvalidDataException($"{path}: record without a parameter-set section.");
            string parameterSet = section[..2];
            string? curve = family == KasFamily.Ecc
                ? curves.GetValueOrDefault(parameterSet) ?? throw new InvalidDataException($"{path}: no curve for {parameterSet}.")
                : null;
            string? variant = stage == KasStage.KeyConfirmation
                ? record.LatestHeader(h => h.StartsWith("CCM AES", StringComparison.Ordinal) || h.StartsWith("CMAC AES", StringComparison.Ordinal) || h.StartsWith("HMAC SHA", StringComparison.Ordinal))
                : null;
            var vector = new KasVector(record, family, stage, scheme, initiator, curve, section[(section.IndexOf(" - ", StringComparison.Ordinal) + 3)..].Trim(), variant);
            if (!ResultPattern().IsMatch(vector.Result))
                throw new InvalidDataException($"{vector}: malformed result '{vector.Result}'.");
            _ = vector.Effect;
            yield return vector;
        }
    }
}
