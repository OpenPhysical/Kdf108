# Database Encryption Key Management

## Problem Description

Database encryption requires careful key management to protect sensitive data while maintaining:
- Performance and scalability
- Ability to rotate keys without re-encrypting all data
- Separation between different types of data (PII, financial, medical, etc.)
- Support for data retention policies and compliance requirements

## Security Requirements

- Different encryption keys for different data classifications
- Support for key rotation without downtime
- Audit trail of key usage
- Performance-optimized key derivation
- Compliance with data protection regulations (GDPR, HIPAA, etc.)

## Recommended Solution

Use hierarchical key derivation with data classification and table-specific context.

### Key Hierarchy

1. **Master Key**: Root encryption key (stored in HSM/KMS)
2. **Table Keys**: Derived per table or data classification
3. **Row Keys**: Optional, for extremely sensitive data requiring per-record encryption

### Parameters

- **Master Key**: 256-bit key from secure key management system
- **Purpose**: Data classification level ("pii-encryption", "financial-data", "audit-logs")
- **Context**: Table name, schema version, and optional tenant ID
- **Output Length**: 32 bytes (AES-256)

## Code Example

### Basic Database Key Manager

```csharp
using Kdf108.Simple;

public class DatabaseKeyManager
{
    private readonly byte[] _masterKey;
    private readonly string _applicationVersion;
    
    public DatabaseKeyManager(byte[] masterKey, string applicationVersion = "v1")
    {
        _masterKey = masterKey ?? throw new ArgumentNullException(nameof(masterKey));
        _applicationVersion = applicationVersion;
    }
    
    /// <summary>
    /// Gets table-specific encryption key based on data classification
    /// </summary>
    public byte[] GetTableEncryptionKey(string tableName, DataClassification classification)
    {
        if (string.IsNullOrEmpty(tableName))
            throw new ArgumentException("Table name cannot be null or empty", nameof(tableName));
            
        var purpose = GetPurposeForClassification(classification);
        var context = BuildTableContext(tableName);
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _masterKey,
            purpose: purpose,
            outputLength: 32,
            context: context
        );
    }
    
    /// <summary>
    /// Gets field-specific key for highly sensitive data
    /// </summary>
    public byte[] GetFieldEncryptionKey(string tableName, string fieldName, DataClassification classification)
    {
        if (string.IsNullOrEmpty(tableName))
            throw new ArgumentException("Table name cannot be null or empty", nameof(tableName));
        if (string.IsNullOrEmpty(fieldName))
            throw new ArgumentException("Field name cannot be null or empty", nameof(fieldName));
            
        var purpose = GetPurposeForClassification(classification);
        var context = BuildFieldContext(tableName, fieldName);
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _masterKey,
            purpose: purpose,
            outputLength: 32,
            context: context
        );
    }
    
    private string GetPurposeForClassification(DataClassification classification)
    {
        return classification switch
        {
            DataClassification.Public => $"public-data-{_applicationVersion}",
            DataClassification.Internal => $"internal-data-{_applicationVersion}",
            DataClassification.Confidential => $"confidential-data-{_applicationVersion}",
            DataClassification.Restricted => $"restricted-data-{_applicationVersion}",
            _ => throw new ArgumentException($"Unknown data classification: {classification}")
        };
    }
    
    private byte[] BuildTableContext(string tableName)
    {
        var contextString = $"table-{tableName.ToLowerInvariant()}";
        return System.Text.Encoding.UTF8.GetBytes(contextString);
    }
    
    private byte[] BuildFieldContext(string tableName, string fieldName)
    {
        var contextString = $"table-{tableName.ToLowerInvariant()}-field-{fieldName.ToLowerInvariant()}";
        return System.Text.Encoding.UTF8.GetBytes(contextString);
    }
}

public enum DataClassification
{
    Public,        // No encryption needed
    Internal,      // Standard encryption
    Confidential,  // Enhanced encryption
    Restricted     // Maximum security encryption
}
```

### Multi-Tenant Database Encryption

```csharp
public class MultiTenantDatabaseKeyManager : DatabaseKeyManager
{
    public MultiTenantDatabaseKeyManager(byte[] masterKey, string applicationVersion = "v1") 
        : base(masterKey, applicationVersion)
    {
    }
    
    /// <summary>
    /// Gets tenant-specific table encryption key
    /// </summary>
    public byte[] GetTenantTableKey(string tenantId, string tableName, DataClassification classification)
    {
        if (string.IsNullOrEmpty(tenantId))
            throw new ArgumentException("Tenant ID cannot be null or empty", nameof(tenantId));
            
        var purpose = GetPurposeForClassification(classification);
        var context = BuildTenantTableContext(tenantId, tableName);
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _masterKey,
            purpose: purpose,
            outputLength: 32,
            context: context
        );
    }
    
    private byte[] BuildTenantTableContext(string tenantId, string tableName)
    {
        var contextString = $"tenant-{tenantId}-table-{tableName.ToLowerInvariant()}";
        return System.Text.Encoding.UTF8.GetBytes(contextString);
    }
}
```

### Key Versioning for Rotation

```csharp
public class VersionedDatabaseKeyManager : DatabaseKeyManager
{
    public VersionedDatabaseKeyManager(byte[] masterKey, string applicationVersion = "v1") 
        : base(masterKey, applicationVersion)
    {
    }
    
    /// <summary>
    /// Gets table encryption key with specific version for key rotation
    /// </summary>
    public byte[] GetVersionedTableKey(string tableName, DataClassification classification, int keyVersion)
    {
        if (keyVersion < 1)
            throw new ArgumentException("Key version must be positive", nameof(keyVersion));
            
        var purpose = $"{GetPurposeForClassification(classification)}-v{keyVersion}";
        var context = BuildTableContext(tableName);
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _masterKey,
            purpose: purpose,
            outputLength: 32,
            context: context
        );
    }
    
    /// <summary>
    /// Gets the current active key version for a table
    /// </summary>
    public int GetCurrentKeyVersion(string tableName)
    {
        // In practice, this would come from your database schema or configuration
        // For this example, we'll use a simple mapping
        return GetStoredKeyVersion(tableName) ?? 1;
    }
    
    private int? GetStoredKeyVersion(string tableName)
    {
        // Implementation would query your key version tracking system
        // Could be stored in database metadata, configuration service, etc.
        return null; // Return null to default to version 1
    }
}
```

## Integration with Entity Framework

```csharp
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

public class EncryptedDbContext : DbContext
{
    private readonly DatabaseKeyManager _keyManager;
    
    public EncryptedDbContext(DbContextOptions<EncryptedDbContext> options, DatabaseKeyManager keyManager)
        : base(options)
    {
        _keyManager = keyManager;
    }
    
    public DbSet<Customer> Customers { get; set; } = null!;
    public DbSet<PaymentInfo> PaymentInfo { get; set; } = null!;
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Configure encryption for sensitive fields
        modelBuilder.Entity<Customer>(entity =>
        {
            entity.Property(e => e.SocialSecurityNumber)
                  .HasConversion(
                      v => EncryptField(v, "customers", "ssn", DataClassification.Restricted),
                      v => DecryptField(v, "customers", "ssn", DataClassification.Restricted));
                      
            entity.Property(e => e.Email)
                  .HasConversion(
                      v => EncryptField(v, "customers", "email", DataClassification.Confidential),
                      v => DecryptField(v, "customers", "email", DataClassification.Confidential));
        });
        
        base.OnModelCreating(modelBuilder);
    }
    
    private string EncryptField(string plaintext, string tableName, string fieldName, DataClassification classification)
    {
        if (string.IsNullOrEmpty(plaintext))
            return plaintext;
            
        var key = _keyManager.GetFieldEncryptionKey(tableName, fieldName, classification);
        
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        
        using var encryptor = aes.CreateEncryptor();
        var plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
        var ciphertextBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);
        
        // Prepend IV to ciphertext
        var result = new byte[aes.IV.Length + ciphertextBytes.Length];
        Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
        Array.Copy(ciphertextBytes, 0, result, aes.IV.Length, ciphertextBytes.Length);
        
        return Convert.ToBase64String(result);
    }
    
    private string DecryptField(string ciphertext, string tableName, string fieldName, DataClassification classification)
    {
        if (string.IsNullOrEmpty(ciphertext))
            return ciphertext;
            
        var key = _keyManager.GetFieldEncryptionKey(tableName, fieldName, classification);
        var data = Convert.FromBase64String(ciphertext);
        
        using var aes = Aes.Create();
        aes.Key = key;
        
        // Extract IV from beginning of data
        var iv = new byte[aes.BlockSize / 8];
        var ciphertextBytes = new byte[data.Length - iv.Length];
        
        Array.Copy(data, 0, iv, 0, iv.Length);
        Array.Copy(data, iv.Length, ciphertextBytes, 0, ciphertextBytes.Length);
        
        aes.IV = iv;
        
        using var decryptor = aes.CreateDecryptor();
        var plaintextBytes = decryptor.TransformFinalBlock(ciphertextBytes, 0, ciphertextBytes.Length);
        
        return System.Text.Encoding.UTF8.GetString(plaintextBytes);
    }
}

// Models
public class Customer
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;        // Encrypted
    public string SocialSecurityNumber { get; set; } = string.Empty; // Encrypted
}

public class PaymentInfo
{
    public int Id { get; set; }
    public int CustomerId { get; set; }
    public string CardNumber { get; set; } = string.Empty;   // Should be encrypted
    public decimal Amount { get; set; }
}
```

## Key Rotation Strategy

```csharp
public class DatabaseKeyRotationManager
{
    private readonly VersionedDatabaseKeyManager _keyManager;
    private readonly IDbContext _dbContext;
    
    public DatabaseKeyRotationManager(VersionedDatabaseKeyManager keyManager, IDbContext dbContext)
    {
        _keyManager = keyManager;
        _dbContext = dbContext;
    }
    
    /// <summary>
    /// Rotates keys for a specific table
    /// </summary>
    public async Task RotateTableKeysAsync(string tableName, DataClassification classification)
    {
        var currentVersion = _keyManager.GetCurrentKeyVersion(tableName);
        var newVersion = currentVersion + 1;
        
        // Update key version in metadata
        await UpdateKeyVersionAsync(tableName, newVersion);
        
        // Schedule background re-encryption of existing data
        await ScheduleReEncryptionAsync(tableName, currentVersion, newVersion);
    }
    
    private async Task UpdateKeyVersionAsync(string tableName, int newVersion)
    {
        // Update your key version tracking system
        // This could be database metadata, configuration service, etc.
        await Task.CompletedTask; // Placeholder
    }
    
    private async Task ScheduleReEncryptionAsync(string tableName, int oldVersion, int newVersion)
    {
        // Schedule background job to re-encrypt data with new key
        // This should be done in batches to avoid performance impact
        await Task.CompletedTask; // Placeholder
    }
}
```

## Security Considerations

### ✅ Best Practices

1. **Master Key Protection**: Store in HSM or cloud KMS service
2. **Data Classification**: Use appropriate encryption strength for data sensitivity
3. **Key Versioning**: Support key rotation without service interruption
4. **Audit Logging**: Log all key derivation and usage events
5. **Context Consistency**: Use consistent naming for tables and fields

### ⚠️ Important Warnings

1. **Performance Impact**: Database encryption affects query performance
2. **Backup Encryption**: Ensure database backups are also encrypted
3. **Index Limitations**: Encrypted fields can't be efficiently indexed
4. **Key Rotation Complexity**: Plan for gradual re-encryption during rotation
5. **Compliance Requirements**: Ensure encryption meets regulatory standards

## Performance Optimization

### Key Caching

```csharp
public class CachedDatabaseKeyManager : DatabaseKeyManager
{
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _cacheExpiry;
    
    public CachedDatabaseKeyManager(byte[] masterKey, IMemoryCache cache, TimeSpan cacheExpiry, string applicationVersion = "v1")
        : base(masterKey, applicationVersion)
    {
        _cache = cache;
        _cacheExpiry = cacheExpiry;
    }
    
    public override byte[] GetTableEncryptionKey(string tableName, DataClassification classification)
    {
        var cacheKey = $"table:{tableName}:{classification}";
        
        if (_cache.TryGetValue(cacheKey, out byte[]? cachedKey) && cachedKey != null)
        {
            return cachedKey;
        }
        
        var key = base.GetTableEncryptionKey(tableName, classification);
        _cache.Set(cacheKey, key, _cacheExpiry);
        
        return key;
    }
}
```

## Testing

```csharp
[Test]
public void DifferentTables_ShouldHaveDifferentKeys()
{
    var manager = new DatabaseKeyManager(TestMasterKey);
    
    var key1 = manager.GetTableEncryptionKey("users", DataClassification.Confidential);
    var key2 = manager.GetTableEncryptionKey("orders", DataClassification.Confidential);
    
    Assert.That(key1, Is.Not.EqualTo(key2));
}

[Test]
public void DifferentClassifications_ShouldHaveDifferentKeys()
{
    var manager = new DatabaseKeyManager(TestMasterKey);
    
    var key1 = manager.GetTableEncryptionKey("users", DataClassification.Internal);
    var key2 = manager.GetTableEncryptionKey("users", DataClassification.Confidential);
    
    Assert.That(key1, Is.Not.EqualTo(key2));
}
```

## Common Pitfalls

1. **Over-encryption**: Not all data needs encryption - classify appropriately
2. **Key storage**: Never store derived keys alongside encrypted data
3. **Query performance**: Consider encryption impact on database queries
4. **Backup security**: Encrypted databases need encrypted backup strategies
5. **Migration complexity**: Plan for schema changes with encrypted fields