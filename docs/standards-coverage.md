# Standards coverage

What Kdf108 implements and how each part is tested. This is a map of this repository's own
evidence, not a third-party validation.

## How it is tested

`dotnet test` runs the fast lane: unit tests, pinned known answers, the 372 SP 800-56C one-step
vectors, and a smoke run of every SP 800-56A shard. It parses no full corpus and takes seconds.

The CAVP gates run every vector in the pinned NIST corpora. Each vector file is one test that
runs all of its vectors and reports every failure. For each gate, `tests/verify-conformance-results.ps1`
then checks three things: the corpus is byte-for-byte the pinned one (SHA-256), nothing failed
or was skipped, and the number of vectors executed equals `tests/conformance-manifest.json`.
CI runs every gate on .NET 9 and .NET 10, and a release cannot publish until they pass.

| Gate | Vectors | What each vector checks |
|---|---:|---|
| CAVP-SP800-108 | 16,000 | the derived key |
| CAVP-SP800-56A-ECC-ZZ | 1,680 | Z, or the right key rejection |
| CAVP-SP800-56A-ECC-KDF | 4,140 | Z and DKM |
| CAVP-SP800-56A-ECC-KC | 90,240 | Z, DKM, MacData, and the tag |
| CAVP-SP800-56A-FFC-ZZ | 672 | Z, or the right key rejection |
| CAVP-SP800-56A-FFC-KDF | 2,352 | Z and DKM |
| CAVP-SP800-56A-FFC-KC | 62,352 | Z, DKM, MacData, and the tag |

Key-rejection vectors pass only if production code raises `InvalidKeyException` for the right
party's key, with the right failure. An error inside the test harness can never count as a
rejection.

## SP 800-108 Rev. 1

- Counter, feedback, and double-pipeline modes with every CAVP counter position and width
  (8, 16, 24, 32), with or without a counter where the mode allows it.
- HMAC with SHA-1, SHA-2, SHA-512/224, SHA-512/256, and SHA-3; AES-CMAC with 128-, 192-, and
  256-bit keys. The NIST corpus covers HMAC-SHA-1/SHA-2 and AES-CMAC; the other hashes are
  covered by unit tests.
- The KMAC KDF (§4.4), checked against the SP 800-185 KMAC samples.
- Output up to 2^32 - 1 bits, partial-byte output, and the counter limit, all checked before any
  PRF work.
- TDEA is not available (SP 800-131A). The corpus's 4,000 TDEA vectors are counted, not run.

## SP 800-56A Rev. 3

- ECC on the twelve NIST prime and binary curves; FFC on the ten Appendix D safe-prime groups
  and FIPS 186-type FB/FC parameters (with evidence replay or a trusted authority).
- Full public-key validation (§5.6.2.3.1 and §5.6.2.3.3), private-key range checks, and
  pairwise consistency on import.
- Every scheme in both families: Ephemeral, Static, One-Flow, Hybrid, Hybrid One-Flow, MQV2,
  and MQV1, with both party roles.
- Forbidden shared secrets are rejected: the point at infinity, and Z in {0, 1, p - 1}.
- Key confirmation (§5.9), unilateral and bilateral, with HMAC, AES-CMAC, and KMAC ("KC").
  The 2016 corpus also contains AES-CCM key-confirmation vectors; Rev. 3 dropped CCM, so the
  test harness checks those tags itself while still running Z and DKM through the library.

## SP 800-56C Rev. 2

- One-step derivation with any approved hash, HMAC (default or supplied salt), or KMAC128/256
  (default or supplied salt, customization "KDF").
- Two-step derivation: HMAC or AES-CMAC extraction, then SP 800-108 expansion with the PRF the
  standard requires, in any of the three modes.
- Security-strength checks against the chosen function.

NIST publishes no SP 800-56C test vectors. The 372 one-step vectors in
`tests/Kdf108.Test/res/vectors/SP800-56C` are unofficial (from the singlestep-kdf project), and the
SP 800-56A KDF and key-confirmation gates exercise the one-step method through 161,436 official
vectors' DKM checks.
