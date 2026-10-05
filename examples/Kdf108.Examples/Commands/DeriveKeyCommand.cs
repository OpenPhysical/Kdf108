using System;
using System.ComponentModel;
using System.Text;
using Org.BouncyCastle.Security;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Kdf108.Examples.Commands;

/// <summary>Derives a key from a key-derivation key with SP 800-108.</summary>
public sealed class DeriveKeyCommand(IAnsiConsole console, ISp800108Kdf kdf, SecureRandom random) : Command<DeriveKeyCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Key-derivation key as hex, at least 16 bytes. Omit it to use a fresh random 32-byte key.")]
        [CommandOption("-k|--key")]
        public string? Key { get; init; }

        [Description("Label: what the key is for")]
        [CommandOption("-l|--label")]
        [DefaultValue("encryption")]
        public string Label { get; init; } = "encryption";

        [Description("Context: who or what the key is bound to")]
        [CommandOption("-c|--context")]
        [DefaultValue("user:42")]
        public string Context { get; init; } = "user:42";

        [Description("Output length in bits")]
        [CommandOption("-b|--bits")]
        [DefaultValue(256)]
        public int Bits { get; init; } = 256;

        [Description("counter, feedback, double-pipeline, or kmac")]
        [CommandOption("-m|--mode")]
        [DefaultValue("counter")]
        public string Mode { get; init; } = "counter";

        [Description("Show the library's log messages")]
        [CommandOption("-v|--verbose")]
        public bool Verbose { get; init; }
    }

    /// <summary>The derivation itself, separate from the console output.</summary>
    public static byte[] Derive(ISp800108Kdf kdf, ReadOnlySpan<byte> key, string mode, string label, string context, int bits)
    {
        if (key.Length < 16)
            throw new ArgumentException("Use a key-derivation key of at least 16 bytes (128 bits).", nameof(key));
        byte[] labelBytes = Encoding.UTF8.GetBytes(label);
        byte[] contextBytes = Encoding.UTF8.GetBytes(context);
        var length = BitLength.Create(bits);
        var prf = Prf.Hmac(NistHashAlgorithm.Sha256);
        byte[] fixedInput = Sp800108.FixedInput(labelBytes, contextBytes, length);

        return mode switch
        {
            "counter" => kdf.Derive(key, prf, labelBytes, contextBytes, length),
            // Feedback mode starts from an IV. An empty IV is allowed; a per-derivation IV is also fine.
            "feedback" => kdf.Derive(key, prf, KeyExpansion.Feedback(fixedInput, ReadOnlySpan<byte>.Empty), length),
            "double-pipeline" => kdf.Derive(key, prf, KeyExpansion.DoublePipeline(fixedInput), length),
            "kmac" => kdf.DeriveKmac(key, KmacVariant.Kmac256, labelBytes, contextBytes, length),
            _ => throw new ArgumentException($"Unknown mode '{mode}'.", nameof(mode))
        };
    }

    public override int Execute(CommandContext context, Settings settings, System.Threading.CancellationToken cancellationToken)
    {
        console.Header("SP 800-108 key derivation");
        try
        {
            byte[] key = settings.Key is null ? SecureRandom.GetNextBytes(random, 32) : Convert.FromHexString(settings.Key);
            byte[] derived = Derive(kdf, key, settings.Mode, settings.Label, settings.Context, settings.Bits);

            console.Write(ConsoleUi.Table(
                ("Key-derivation key", settings.Key is null ? "random 32 bytes (pass --key to choose)" : ConsoleUi.Hex(key)),
                ("Mode", settings.Mode == "kmac" ? "KMAC256 (§4.4)" : $"{settings.Mode}, HMAC-SHA-256, 32-bit counter"),
                ("Label", settings.Label),
                ("Context", settings.Context),
                ("Output", $"{settings.Bits} bits: {ConsoleUi.Hex(derived)}")));
            console.MarkupLine("[dim]A different label or context gives an independent key. Clear key material when you are done with it.[/]");
            Array.Clear(key);
            Array.Clear(derived);
            return 0;
        }
        catch (Exception ex) when (ex is Kdf108Exception or ArgumentException or FormatException)
        {
            return console.Error(ex);
        }
    }
}
