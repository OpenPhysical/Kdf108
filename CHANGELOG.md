# Changelog

Notable changes for each release are documented here.

## [3.0.0] - 2026-10-04

Version 3 is a new API. See the [migration guide](docs/migration-v3.md) for the mapping from 2.x.

### Added

- SP 800-56A Rev. 3 key agreement for ECC (twelve NIST curves) and FFC (safe-prime groups and
  FIPS 186-type parameters), with every scheme and both party roles under the same method names.
- Full public-key validation, private-key range checks, and pairwise consistency on key import.
- SP 800-56A key confirmation with HMAC, AES-CMAC, and KMAC.
- SP 800-56C Rev. 2 one-step and two-step key derivation.
- The SP 800-108 Rev. 1 KMAC KDF.
- Dependency-injection services (`AddKdf108()`) that log through `ILogger<T>` and never log secrets.
- CAVP gates that run every vector in the pinned NIST SP 800-108 and SP 800-56A corpora
  (177,436 vectors) on .NET 9 and .NET 10 and verify exact execution counts and corpus hashes.
- .NET 10 target.

### Changed

- One consistent public API in the `Kdf108` namespace: static functions plus mirroring services,
  spans in, new arrays out, `BitLength` for every length, and one exception hierarchy.
- Raised the minimum supported runtime from .NET 8 to .NET 9.
- SP 800-108 counter widths are limited to the 8, 16, 24, and 32 bits that SP 800-108 testing defines.
- Releases publish only after the full conformance workflow passes.

### Fixed

- Counter mode computed every PRF block twice and did not clear the blocks it returned.
- KMAC key confirmation used an empty customization string instead of "KC".
- FFC MQV did not check that the local ephemeral key used the same domain.
- EC public keys with x = 0 or y = 0, which are valid, were rejected.
- Non-octet counter widths were encoded as whole bytes, which is not the SP 800-108 encoding.
- Feedback and double-pipeline modes now keep exactly the requested number of bits.
- The SP 800-56C vector test silently skipped 152 of 168 salted HMAC vectors.
- The ECC key-confirmation harness built MacData from padded P-521 coordinates (318 failures).
- The release workflow ran no SP 800-56A vectors.

### Removed

- The legacy SP 800-108 engine, factory, options, and validator layer; the duplicate SP 800-56A
  ECC model; the legacy SP 800-56C pipeline; `Kdf108.Simple`; the debug helpers; and the
  FluentValidation dependency.
