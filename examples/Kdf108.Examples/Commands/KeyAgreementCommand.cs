using System;
using System.ComponentModel;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Kdf108.Examples.Commands;

/// <summary>Runs <see cref="KeyAgreementWalkthrough"/> and shows the outcome.</summary>
public sealed class KeyAgreementCommand(IAnsiConsole console, KeyAgreementWalkthrough walkthrough) : Command<KeyAgreementCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("ecc or ffc")]
        [CommandOption("-f|--family")]
        [DefaultValue("ecc")]
        public string Family { get; init; } = "ecc";

        [Description("ephemeral, static, one-flow, hybrid, hybrid-one-flow, mqv2, or mqv1")]
        [CommandOption("-s|--scheme")]
        [DefaultValue("ephemeral")]
        public string Scheme { get; init; } = "ephemeral";

        [Description("one-step or two-step")]
        [CommandOption("-k|--kdf")]
        [DefaultValue("one-step")]
        public string Kdf { get; init; } = "one-step";

        [Description("Run bilateral key confirmation")]
        [CommandOption("-c|--confirm")]
        public bool Confirm { get; init; }

        [Description("Show the library's log messages")]
        [CommandOption("-v|--verbose")]
        public bool Verbose { get; init; }
    }

    public override int Execute(CommandContext context, Settings settings, System.Threading.CancellationToken cancellationToken)
    {
        console.Header($"SP 800-56A {settings.Family.ToUpperInvariant()} {settings.Scheme} + SP 800-56C {settings.Kdf}");
        try
        {
            KeyAgreementWalkthrough.Result result = walkthrough.Run(settings.Family, settings.Scheme, settings.Kdf, settings.Confirm);
            bool match = result.KeyU.AsSpan().SequenceEqual(result.KeyV);
            console.Write(ConsoleUi.Table(
                ("Domain", settings.Family == "ecc" ? "P-256" : "ffdhe2048"),
                ("Shared secret Z", $"{result.ZBits} bits (cleared after use)"),
                ("Party U key", ConsoleUi.Hex(result.KeyU)),
                ("Party V key", ConsoleUi.Hex(result.KeyV)),
                ("Keys match", match ? "yes" : "NO"),
                ("Key confirmation", result.TagsVerified switch { null => "not run (pass --confirm)", true => "both tags verified", false => "FAILED" })));
            console.MarkupLine("[dim]Static keys authenticate the parties; purely ephemeral schemes need authentication elsewhere (for example signatures).[/]");
            return match && result.TagsVerified != false ? 0 : 1;
        }
        catch (Exception ex) when (ex is Kdf108Exception or ArgumentException)
        {
            return console.Error(ex);
        }
    }
}
