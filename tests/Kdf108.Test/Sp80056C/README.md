# SP 800-56C Test Vectors

This directory contains test implementations for NIST SP 800-56C Rev 2 "Recommendation for Key-Derivation Methods in Key-Establishment Schemes".

## Test Vector Sources

The test vectors are from unofficial sources as NIST does not provide official SP 800-56C test vectors:
- Source: https://github.com/patrickfav/singlestep-kdf/wiki/NIST-SP-800-56C-Rev1:-Non-Official-Test-Vectors

## Implemented Tests

### Hash-based One-Step KDF
The following hash algorithms are tested:
- **SHA-1**: 68 test vectors
- **SHA-256**: 70 test vectors  
- **SHA-512**: 70 test vectors

### Test Categories
1. **Basic functionality tests** - Verify KDF produces correct output
2. **Variable length outputs** - Test different output lengths (L parameter)
3. **Empty FixedInfo** - Test vectors with no additional info
4. **Small outputs** - Test vectors with L ≤ 8 bytes
5. **Large outputs** - Test vectors with L > 32 bytes

## Implemented Tests

### HMAC-based One-Step KDF
The following HMAC algorithms are tested:
- **HMAC-SHA256**: Test vectors validated
- **HMAC-SHA512**: Test vectors validated

The implementation uses the `Sp80056CHmacKdf` class which follows the SP 800-56C specification for HMAC-based key derivation.

### Two-Step KDF
SP 800-56C Rev 2 also defines a two-step key derivation method which is not covered by these test vectors.

## Implementation Notes

The SP 800-56C One-Step KDF is implemented using the SP 800-56A Concatenation KDF (`Sp80056AConcatKdf`) which follows the same algorithm:
- Counter || Z || FixedInfo pattern
- 32-bit big-endian counter starting at 1
- Hash-based derivation

The implementation supports:
- Hash-based KDF: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- HMAC-based KDF: HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512
- Variable output lengths
- Optional FixedInfo parameter
- Optional salt parameter for HMAC-based KDF

## Running Tests

To run only the SP 800-56C test vectors:
```bash
dotnet test --filter "FullyQualifiedName~Kdf108.Test.Sp80056C.Sp80056CTestVectorTests"
```

To run a specific hash algorithm:
```bash
dotnet test --filter "FullyQualifiedName~Kdf108.Test.Sp80056C.Sp80056CTestVectorTests.TestSp80056COneStepKdf_SHA256Vectors"
```