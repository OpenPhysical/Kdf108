# Multi-Tenant Application Key Separation

## Problem Description

In multi-tenant applications, each tenant's data must be cryptographically isolated to prevent cross-tenant data access. Using a single encryption key for all tenants creates security risks if the key is compromised or if there are implementation bugs.

## Security Requirements

- Each tenant must have cryptographically independent keys
- Keys should be derived from a secure master key
- Tenant isolation must be maintained even if one tenant's key is compromised
- Key derivation should be deterministic for the same tenant
- Support for different key types (encryption, authentication, etc.)

## Recommended Solution

Use KDF with tenant-specific context data to derive independent keys for each tenant.

### Parameters

- **Master Key**: 256-bit cryptographically secure random key (stored securely)
- **Purpose**: Specific to key use case (e.g., "data-encryption", "auth-token")
- **Context**: Tenant identifier combined with application context
- **Output Length**: Based on target algorithm (32 bytes for AES-256)

## Code Example

```csharp
using Kdf108.Simple;

public class MultiTenantKeyManager
{
    private readonly byte[] _masterKey;
    
    public MultiTenantKeyManager(byte[] masterKey)
    {
        _masterKey = masterKey ?? throw new ArgumentNullException(nameof(masterKey));
    }
    
    /// <summary>
    /// Derives a tenant-specific encryption key
    /// </summary>
    public byte[] GetTenantEncryptionKey(string tenantId)
    {
        if (string.IsNullOrEmpty(tenantId))
            throw new ArgumentException("Tenant ID cannot be null or empty", nameof(tenantId));
            
        var context = System.Text.Encoding.UTF8.GetBytes($"tenant-{tenantId}");
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _masterKey,
            purpose: "data-encryption-v1",
            outputLength: 32,
            context: context
        );
    }
    
    /// <summary>
    /// Derives a tenant-specific authentication key
    /// </summary>
    public byte[] GetTenantAuthKey(string tenantId)
    {
        if (string.IsNullOrEmpty(tenantId))
            throw new ArgumentException("Tenant ID cannot be null or empty", nameof(tenantId));
            
        var context = System.Text.Encoding.UTF8.GetBytes($"tenant-{tenantId}");
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _masterKey,
            purpose: "authentication-v1",
            outputLength: 32,
            context: context
        );
    }
}

// Usage example
var masterKey = Convert.FromHexString("your-256-bit-master-key-in-hex");
var keyManager = new MultiTenantKeyManager(masterKey);

// Each tenant gets unique keys
var tenant1EncKey = keyManager.GetTenantEncryptionKey("tenant-001");
var tenant2EncKey = keyManager.GetTenantEncryptionKey("tenant-002");

// Keys are different even for the same tenant but different purposes
var tenant1AuthKey = keyManager.GetTenantAuthKey("tenant-001");
```

## Security Considerations

### ✅ Best Practices

1. **Master Key Security**: Store the master key in a Hardware Security Module (HSM) or secure key management service
2. **Tenant ID Validation**: Validate tenant IDs to prevent injection attacks
3. **Purpose Versioning**: Include version numbers in purpose strings to support key rotation
4. **Deterministic Derivation**: Same inputs always produce the same key (good for caching)

### ⚠️ Important Warnings

1. **Master Key Compromise**: If the master key is compromised, ALL tenant keys are compromised
2. **Tenant ID Uniqueness**: Ensure tenant IDs are unique and cannot be guessed or enumerated
3. **Context Consistency**: Use consistent context formatting across your application
4. **Key Lifecycle**: Plan for key rotation and migration strategies

## Advanced Configuration

### Different Security Levels per Tenant

```csharp
public byte[] GetTenantKeyWithSecurityLevel(string tenantId, string securityLevel)
{
    var context = System.Text.Encoding.UTF8.GetBytes($"tenant-{tenantId}-{securityLevel}");
    
    var outputLength = securityLevel switch
    {
        "standard" => 32,  // AES-256
        "high" => 64,      // Larger key material for future algorithms
        _ => throw new ArgumentException($"Unknown security level: {securityLevel}")
    };
    
    return SecureKeyDerivation.DeriveKey(_masterKey, "data-encryption-v1", outputLength, context);
}
```

### Hierarchical Key Structure

```csharp
public byte[] GetDepartmentKey(string tenantId, string departmentId)
{
    var context = System.Text.Encoding.UTF8.GetBytes($"tenant-{tenantId}-dept-{departmentId}");
    
    return SecureKeyDerivation.DeriveKey(
        masterKey: _masterKey,
        purpose: "department-isolation-v1",
        outputLength: 32,
        context: context
    );
}
```

## Testing Recommendations

```csharp
[Test]
public void DifferentTenants_ShouldHaveDifferentKeys()
{
    var keyManager = new MultiTenantKeyManager(TestMasterKey);
    
    var key1 = keyManager.GetTenantEncryptionKey("tenant-001");
    var key2 = keyManager.GetTenantEncryptionKey("tenant-002");
    
    Assert.That(key1, Is.Not.EqualTo(key2));
}

[Test]
public void SameTenant_ShouldHaveConsistentKeys()
{
    var keyManager = new MultiTenantKeyManager(TestMasterKey);
    
    var key1 = keyManager.GetTenantEncryptionKey("tenant-001");
    var key2 = keyManager.GetTenantEncryptionKey("tenant-001");
    
    Assert.That(key1, Is.EqualTo(key2));
}
```

## Common Pitfalls

1. **Using tenant data as master key**: Never use tenant-provided data as cryptographic material
2. **Weak tenant IDs**: Avoid sequential or predictable tenant identifiers
3. **Missing context**: Don't skip context data - it provides crucial key separation
4. **Inconsistent formatting**: Maintain consistent tenant ID and context formatting
5. **Purpose reuse**: Use different purposes for different key types to maintain separation