using System;
using System.Collections.Generic;
using System.Linq;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Kdf108.Examples.Commands;

/// <summary>
/// Checks a handful of published known answers byte for byte. The full NIST corpora (177,000+
/// vectors) run in the test suite's CAVP gates; this is a quick self-check of an installed build.
/// </summary>
public sealed class VerifyVectorsCommand(IAnsiConsole console, ISp800108Kdf kdf108, ISp80056CKdf kdf56C, IEcKeyAgreement ecc) : Command
{
    public sealed record Outcome(string Name, string Source, bool Passed);

    public static IReadOnlyList<Outcome> Run(ISp800108Kdf kdf108, ISp80056CKdf kdf56C, IEcKeyAgreement ecc)
    {
        static byte[] H(string hex) => Convert.FromHexString(hex);
        var outcomes = new List<Outcome>();
        void Check(string name, string source, Func<byte[]> actual, string expected)
        {
            bool passed;
            try { passed = actual().AsSpan().SequenceEqual(H(expected)); }
            catch (Kdf108Exception) { passed = false; }
            outcomes.Add(new Outcome(name, source, passed));
        }

        Check("SP 800-108 counter mode, HMAC-SHA-256", "NIST CAVP KDFCTR_gen.rsp, r=32, before fixed, COUNT=0",
            () => kdf108.Derive(H("dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0"), Prf.Hmac(NistHashAlgorithm.Sha256),
                KeyExpansion.Counter(H("01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac")),
                BitLength.Create(128)),
            "10621342bfb0fd40046c0e29f2cfdbf0");

        Check("SP 800-108 KMAC128", "NIST SP 800-185 KMAC sample #1",
            () => kdf108.DeriveKmac(H("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"), KmacVariant.Kmac128,
                default, H("00010203"), BitLength.Create(256)),
            "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E");

        var p256 = EcDomain.Named(EcCurve.P256);
        byte[] Z() => ecc.Ephemeral(
            EcEphemeralKeyPair.Import(p256, H("d10f3f9b31bd3dc826b215344ba1746090cf11d5476bf8eafc0b5bfdbb7182b5"),
                H("04" + "8c1934b6688635531a54a049755417865db7d93d5cab1b2b3360eda96032f07c" + "bfdd434a49e78c13886bd3d0b5322e74b35b6905f65274266cd3b0dc18645733")),
            EcEphemeralPublicKey.Import(p256,
                H("04" + "b2240711b80d28f7b22b9c0e17efbcb6c11d1aca3e1fb5f1c3de9e9e8a612c9a" + "597a619dc69436837e0d05e9974da9ea83bc03aa9aae3b1156f5b2a02f0df780")));
        const string kas = "NIST CAVP KAS ECC Ephemeral Unified, P-256, SHA-256, COUNT=0";
        Check("SP 800-56A ECC CDH (Ephemeral Unified)", kas, Z, "b2936bd75eee3f815742a7a545c080485bea730997fae4422aacdadf238d7afb");
        Check("SP 800-56C one-step, SHA-256 (DKM)", kas,
            () => kdf56C.OneStep(Z(), OneStepFunction.HashFunction(NistHashAlgorithm.Sha256),
                H("a1b2c3d4e5434156536964d8693c637f233a2254abcf188fe5a1669926fd34cfecbd0082cc6f3542abb3005c31e55f"),
                BitLength.Create(128), SecurityStrength.Bits128),
            "66b6e1389750f7f390bf1e0f0f4cd7dc");

        return outcomes;
    }

    public override int Execute(CommandContext context, System.Threading.CancellationToken cancellationToken)
    {
        console.Header("Known-answer self-check");
        var outcomes = Run(kdf108, kdf56C, ecc);
        var table = new Table().Border(TableBorder.Rounded).AddColumn("Check").AddColumn("Source").AddColumn("Result");
        foreach (var o in outcomes)
            table.AddRow(Markup.Escape(o.Name), Markup.Escape(o.Source), o.Passed ? "[green]pass[/]" : "[red]FAIL[/]");
        console.Write(table);
        return outcomes.All(o => o.Passed) ? 0 : 1;
    }
}
