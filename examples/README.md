# KDF-108 Examples

This directory contains comprehensive, well-documented examples demonstrating the KDF-108 cryptographic library functionality.

## Quick Start

### From Any Directory (Recommended)

Use the provided shell scripts to run examples from anywhere:

**Linux/macOS:**
```bash
# From project root or any subdirectory
./kdf108-examples.sh --help
./kdf108-examples.sh derive-key --master-key 404142434445464748494A4B4C4D4E4F --purpose encryption
./kdf108-examples.sh secure-channel --curve P-256 --session-id test-session  
./kdf108-examples.sh minimal
```

**Windows:**
```cmd
# From project root or any subdirectory
kdf108-examples.cmd --help
kdf108-examples.cmd derive-key --master-key 404142434445464748494A4B4C4D4E4F --purpose encryption
kdf108-examples.cmd secure-channel --curve P-256 --session-id test-session
kdf108-examples.cmd minimal
```

### From Examples Directory

```bash
cd examples/Kdf108.Examples
dotnet run -- --help
```

## Available Commands

### 🔑 `derive-key` - Basic Key Derivation

Demonstrates SP 800-108 key derivation with customizable parameters.

```bash
./kdf108-examples.sh derive-key \
  --master-key 404142434445464748494A4B4C4D4E4F \
  --purpose encryption \
  --output-length 32 \
  --context 73657373696F6E2D30303031 \
  --verbose
```

**Features:**
- Customizable master key (hex format)
- Configurable purpose/label
- Variable output length
- Optional context data
- Progress visualization
- Detailed technical information in verbose mode

### 🔐 `secure-channel` - ECDH + KDF Pipeline

Complete demonstration of establishing secure communication channels using ECDH key agreement followed by key derivation.

```bash
./kdf108-examples.sh secure-channel \
  --curve P-256 \
  --session-id secure-session-001 \
  --verbose
```

**Features:**
- ECDH key pair generation for both parties
- Key agreement demonstration
- Multiple derived keys (encryption, authentication, key wrapping, nonce)
- Security properties explanation
- Support for P-256, P-384, P-521 curves

### 📊 `benchmark` - Performance Testing

Measures KDF operations per second and ECDH performance across different configurations.

```bash
./kdf108-examples.sh benchmark \
  --iterations 10000 \
  --include-ecdh \
  --verbose
```

**Features:**
- KDF performance testing for different key sizes
- ECDH benchmarks for all supported curves  
- Operations per second metrics
- Average timing per operation
- Progress bars with real-time updates

### ✅ `test-vectors` - NIST Validation

Validates the implementation against known test vectors from NIST specifications.

```bash
./kdf108-examples.sh test-vectors \
  --verbose \
  --basic-only
```

**Features:**
- SP 800-108 KDF test vectors
- SP 800-56A ECDH test vectors
- Comprehensive validation reporting
- Success/failure tracking
- Known vs. computed result comparison

### 🧙 `interactive` - Guided Wizard

Step-by-step interactive wizard for beginners with explanations and learning mode.

```bash
./kdf108-examples.sh interactive --verbose
```

**Features:**
- Scenario selection (Basic KDF, ECDH, Multiple Keys, Learning)
- Guided prompts with helpful defaults
- Educational explanations
- Learning mode with KDF theory
- Visual progress and results

### 📚 `minimal` - Simple Examples

Clean, minimal examples focusing on core functionality without complex UI.

```bash
./kdf108-examples.sh minimal --verbose
```

**Features:**
- Basic key derivation example
- Multiple keys from one master
- Context-based key separation
- Clean output focused on core concepts

## Example Scenarios

### Scenario 1: Basic Application Key Derivation

```bash
# Derive encryption key for an application
./kdf108-examples.sh derive-key \
  --master-key $(openssl rand -hex 32) \
  --purpose "app-encryption-v1" \
  --output-length 32
```

### Scenario 2: Secure Communication Setup

```bash
# Establish secure channel with high-security curve
./kdf108-examples.sh secure-channel \
  --curve P-521 \
  --session-id "secure-comms-$(date +%s)"
```

### Scenario 3: Performance Analysis

```bash
# Comprehensive performance testing
./kdf108-examples.sh benchmark \
  --iterations 50000 \
  --include-ecdh \
  --verbose
```

### Scenario 4: Implementation Validation

```bash
# Validate against NIST test vectors
./kdf108-examples.sh test-vectors --verbose
```

## Security Notes

- ⚠️ **Never use hardcoded keys in production** - Examples use fixed keys for demonstration only
- 🔒 **Context data enhances security** - Use unique context for each application/user
- 🔄 **Rotate keys regularly** - Establish key rotation policies
- 📝 **Log derivation parameters** - Maintain audit trails for compliance
- 🔍 **Validate all inputs** - The library performs comprehensive validation

## Technical Details

- **KDF Algorithm**: HMAC-SHA256 in Counter Mode (SP 800-108)
- **Key Agreement**: ECDH on NIST curves (SP 800-56A)  
- **Supported Curves**: P-256, P-384, P-521
- **Output Validation**: All operations include extensive validation
- **Logging**: Structured logging with Microsoft.Extensions.Logging
- **Error Handling**: Descriptive exceptions with clear error messages

## Troubleshooting

### Common Issues

1. **"No such file or directory"** - Ensure you're running from the project root
2. **log4net errors on macOS** - These are cosmetic warnings and don't affect functionality
3. **Build errors** - Run `dotnet restore` and `dotnet build` in the solution root
4. **Permission denied** - Make scripts executable with `chmod +x kdf108-examples.sh`

### Getting Help

- Use `--help` on any command for detailed usage
- Use `--verbose` for detailed technical output
- Check the main project README for additional documentation
- All examples include explanatory output and security guidance