# SP 800-56C Test Vectors

This directory contains tests for NIST SP 800-56C Rev. 2, plus clearly labelled historical
Rev. 1 vectors.

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

The Rev. 2 API is exercised by `Sp80056CTypedApiTests` through immutable one-step and two-step
requests.

### Two-Step KDF
The unofficial vector files do not cover the Rev. 2 two-step method. Independent pinned-answer
tests cover its extraction and expansion behavior.

## Implementation Notes

`Sp80056COneStep` implements the Rev. 2 `Counter || Z || FixedInfo` construction directly with
a 32-bit big-endian counter starting at 1. The typed API supports the approved SHA-1, SHA-2,
SHA-3, HMAC, KMAC128, and KMAC256 choices, including default or caller-supplied salts and
non-octet output lengths.

## Running Tests

To run only the SP 800-56C test vectors:
```bash
dotnet test --filter "FullyQualifiedName~Kdf108.Test.Sp80056C.Sp80056CTestVectorTests"
```

To run a specific hash algorithm:
```bash
dotnet test --filter "FullyQualifiedName~Kdf108.Test.Sp80056C.Sp80056CTestVectorTests.TestSp80056COneStepKdf_SHA256Vectors"
```
