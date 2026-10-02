# Standards coverage

This matrix records the implemented surface and its executable evidence. It is a maintenance
map for this repository, not a third-party validation statement.

## SP 800-56C Rev. 2

- One-step derivation implements hash, HMAC, KMAC128, and KMAC256 auxiliary functions.
- Hash choices include SHA-1, the SHA-2 family and truncated SHA-512 variants, and the SHA-3
  family listed by the recommendation.
- HMAC and KMAC default salts, the KMAC `KDF` customization string, the 32-bit counter,
  partial-bit output, and security-strength bounds are enforced by typed requests.
- Two-step derivation permits HMAC extraction with the same HMAC for expansion, or
  AES-N-CMAC extraction with AES-128-CMAC expansion.
- Counter, feedback, and double-pipeline expansion use SP 800-108 fixed input and preserve
  non-octet output lengths.
- Multiple expansions require pairwise-distinct FixedInfo values.

Evidence: `Sp80056CTypedApiTests`, the SP 800-108 response-vector suites, and the negative
validation suites. The historical files under `tests/Kdf108.Test/res/vectors/SP800-56C` are
unofficial Rev. 1 vectors and remain labelled as such.

## SP 800-56A Rev. 3

- Approved NIST prime and binary elliptic curves are registered.
- ECC DH and MQV primitives validate imported keys and preserve fixed-width field-element
  encoding.
- FFC DH and MQV primitives support the named safe-prime groups in Appendix D, with distinct
  static and ephemeral key types, subgroup validation, and fixed-width encoding.
- FFC ephemeral, static, one-flow, hybrid, hybrid one-flow, MQV1, and MQV2 computations use
  role-specific entry points and the mandated shared-secret ordering.
- Unilateral and bilateral key-confirmation `MacData` ordering, HMAC, KMAC, AES-CMAC,
  security-strength checks, tag truncation, and constant-time verification are implemented.

Evidence: the SP 800-56A CAVP resources, focused FFC role-symmetry tests, key-validation tests,
and independent key-confirmation MAC tests. Vector-backed tests are mandatory only when their
test cases are not marked `Explicit`; explicit diagnostic fixtures are not counted as a release
gate.

## Release gate

The release workflow restores, builds with nullable analysis enabled and zero warnings, and runs
the test suite for both `net9.0` and `net10.0`. Any skipped or explicit diagnostic fixture is
outside that gate and must not be cited as passing evidence.
