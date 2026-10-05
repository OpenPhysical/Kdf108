# Kdf108 examples

A small command-line app that shows the library in use. It is not part of the NuGet package.
Each command's logic is short enough to read in one sitting, and the test suite runs every
command to make sure the output here stays true.

```bash
dotnet run --project examples/Kdf108.Examples -- <command> [options]
```

## derive-key

Derives a key with SP 800-108 from a key-derivation key, a label, and a context.

```bash
dotnet run --project examples/Kdf108.Examples -- derive-key --label encryption --context user:42 --bits 256
dotnet run --project examples/Kdf108.Examples -- derive-key --key 000102030405060708090a0b0c0d0e0f --mode kmac
```

`--mode` is `counter` (the default), `feedback`, `double-pipeline`, or `kmac`. Without `--key`
the command uses a fresh random key. Keys shorter than 16 bytes are refused.

## key-agreement

Plays both parties: each generates keys, they agree on Z with an SP 800-56A scheme, derive keys
from Z with SP 800-56C, and optionally confirm them with bilateral key confirmation.

```bash
dotnet run --project examples/Kdf108.Examples -- key-agreement --family ecc --scheme hybrid --kdf two-step --confirm
```

`--family` is `ecc` (P-256) or `ffc` (ffdhe2048). `--scheme` is `ephemeral`, `static`,
`one-flow`, `hybrid`, `hybrid-one-flow`, `mqv2`, or `mqv1`. `--kdf` is `one-step` or `two-step`.

## verify-vectors

Checks a few published NIST known answers byte for byte and exits non-zero on any mismatch. The
full corpora run in the test suite's CAVP gates.

```bash
dotnet run --project examples/Kdf108.Examples -- verify-vectors
```

## How it is put together

The app uses Spectre.Console.Cli with Microsoft.Extensions.DependencyInjection. `ExampleApp`
registers the Kdf108 services with `AddKdf108()`, a logger, and the random source; commands get
what they need through their constructors. `--verbose` turns on the library's Debug log messages.
