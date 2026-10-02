# Changelog

Notable changes for each release are documented here.

## [3.0.0] - Unreleased

### Added

- SP 800-56A elliptic-curve key agreement models, validation, and CAVP coverage.
- SP 800-56C one-step and two-step key-derivation pipelines and test vectors.
- Standards-safe SP 800-56C request types that prevent forbidden auxiliary-function and expansion combinations.
- Typed factories, simplified key-derivation APIs, debug helpers, examples, and scenario documentation.
- SP 800-108 support for counter widths from 1 through 32 bits and non-octet output lengths.
- .NET 10 target and CI support.

### Changed

- Raised the minimum supported runtime from .NET 8 to .NET 9.
- Replaced the mutable SP 800-56C options surface with immutable one-step and two-step request types.
- Centralized counter encoding, leftmost-bit truncation, fixed-input validation, label encoding, and CMAC key validation.
- Encoded labels with strict UTF-8 instead of lossy ASCII conversion.
- Required exact AES-CMAC, two-key TDES-CMAC, and three-key TDES-CMAC key sizes.
- Applied configured output limits to public fixed-input derivation entry points.
- Updated log4net to 3.4.0.
- Organized SP 800-108, SP 800-56A, and SP 800-56C tests and reference vectors by standard.

### Fixed

- Prevented non-octet counters from truncating and repeating earlier counter blocks.
- Preserved and masked requested partial-byte output in feedback and double-pipeline modes.
- Prevented distinct non-ASCII labels from collapsing to identical derivation inputs.
- Removed silent CMAC key padding and truncation.
- Removed nullable build warnings in CAVP and example logging code.

### Validation

- The release test suite passes on .NET 9 and .NET 10.
- Solution restore and build complete with zero warnings.
