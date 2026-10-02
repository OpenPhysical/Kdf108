# Backup System Encryption

## Problem Description

Backup systems require robust encryption strategies that balance security with operational requirements:
- Long-term data protection (backups may be stored for years)
- Key recovery capabilities when primary systems are unavailable
- Support for different backup types (full, incremental, differential)
- Compliance with data retention and destruction policies
- Protection against both external threats and insider access

## Security Requirements

- Encryption keys must survive longer than the backup retention period
- Key recovery must be possible without compromising current operational keys
- Different backup generations should use different encryption keys
- Support for secure key escrow and emergency recovery procedures
- Audit trail of backup encryption and decryption operations

## Recommended Solution

Use hierarchical key derivation with backup-specific context and temporal separation.

### Key Hierarchy

1. **Archive Master Key**: Long-term key stored in secure offline storage
2. **Backup Generation Keys**: Derived per backup cycle (daily, weekly, monthly)
3. **Content Keys**: Derived per backup file or data classification

### Parameters

- **Master Key**: 256-bit archive master key (offline storage + escrow)
- **Purpose**: Backup type and classification ("daily-backup", "archive-backup")
- **Context**: Timestamp, backup set ID, and data classification
- **Output Length**: 32 bytes (AES-256)

## Code Example

### Basic Backup Encryption Manager

```csharp
using Kdf108.Simple;
using System.Security.Cryptography;

public class BackupEncryptionManager
{
    private readonly byte[] _archiveMasterKey;
    private readonly string _backupSystemId;
    
    public BackupEncryptionManager(byte[] archiveMasterKey, string backupSystemId)
    {
        _archiveMasterKey = archiveMasterKey ?? throw new ArgumentNullException(nameof(archiveMasterKey));
        _backupSystemId = backupSystemId ?? throw new ArgumentNullException(nameof(backupSystemId));
    }
    
    /// <summary>
    /// Derives encryption key for a backup generation
    /// </summary>
    public byte[] GetBackupGenerationKey(BackupType backupType, DateTimeOffset backupDate, string backupSetId)
    {
        if (string.IsNullOrEmpty(backupSetId))
            throw new ArgumentException("Backup set ID cannot be null or empty", nameof(backupSetId));
            
        var purpose = GetPurposeForBackupType(backupType);
        var context = BuildBackupContext(backupDate, backupSetId);
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _archiveMasterKey,
            purpose: purpose,
            outputLength: 32,
            context: context
        );
    }
    
    /// <summary>
    /// Derives content-specific encryption key
    /// </summary>
    public byte[] GetContentEncryptionKey(string backupSetId, string contentPath, DataClassification classification)
    {
        if (string.IsNullOrEmpty(backupSetId))
            throw new ArgumentException("Backup set ID cannot be null or empty", nameof(backupSetId));
        if (string.IsNullOrEmpty(contentPath))
            throw new ArgumentException("Content path cannot be null or empty", nameof(contentPath));
            
        var purpose = GetPurposeForClassification(classification);
        var context = BuildContentContext(backupSetId, contentPath);
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _archiveMasterKey,
            purpose: purpose,
            outputLength: 32,
            context: context
        );
    }
    
    /// <summary>
    /// Creates encrypted backup metadata including key recovery information
    /// </summary>
    public BackupMetadata CreateBackupMetadata(string backupSetId, BackupType backupType, DateTimeOffset backupDate)
    {
        var generationKey = GetBackupGenerationKey(backupType, backupDate, backupSetId);
        
        return new BackupMetadata
        {
            BackupSetId = backupSetId,
            BackupType = backupType,
            BackupDate = backupDate,
            SystemId = _backupSystemId,
            KeyDerivationInfo = new KeyDerivationInfo
            {
                Purpose = GetPurposeForBackupType(backupType),
                Context = Convert.ToBase64String(BuildBackupContext(backupDate, backupSetId)),
                Algorithm = "HMAC-SHA256-Counter-Mode",
                OutputLength = 32
            }
        };
    }
    
    private string GetPurposeForBackupType(BackupType backupType)
    {
        return backupType switch
        {
            BackupType.Full => "full-backup-v1",
            BackupType.Incremental => "incremental-backup-v1",
            BackupType.Differential => "differential-backup-v1",
            BackupType.Archive => "archive-backup-v1",
            _ => throw new ArgumentException($"Unknown backup type: {backupType}")
        };
    }
    
    private string GetPurposeForClassification(DataClassification classification)
    {
        return classification switch
        {
            DataClassification.Public => "backup-public-v1",
            DataClassification.Internal => "backup-internal-v1",
            DataClassification.Confidential => "backup-confidential-v1",
            DataClassification.Restricted => "backup-restricted-v1",
            _ => throw new ArgumentException($"Unknown data classification: {classification}")
        };
    }
    
    private byte[] BuildBackupContext(DateTimeOffset backupDate, string backupSetId)
    {
        // Use date in format that groups by day but includes time for uniqueness
        var dateString = backupDate.ToString("yyyy-MM-dd-HH-mm");
        var contextString = $"system-{_backupSystemId}-date-{dateString}-set-{backupSetId}";
        return System.Text.Encoding.UTF8.GetBytes(contextString);
    }
    
    private byte[] BuildContentContext(string backupSetId, string contentPath)
    {
        // Normalize path and create stable context
        var normalizedPath = contentPath.Replace('\\', '/').ToLowerInvariant();
        var contextString = $"system-{_backupSystemId}-set-{backupSetId}-path-{normalizedPath}";
        return System.Text.Encoding.UTF8.GetBytes(contextString);
    }
}

public enum BackupType
{
    Full,
    Incremental,
    Differential,
    Archive
}

public enum DataClassification
{
    Public,
    Internal,
    Confidential,
    Restricted
}

public class BackupMetadata
{
    public string BackupSetId { get; set; } = string.Empty;
    public BackupType BackupType { get; set; }
    public DateTimeOffset BackupDate { get; set; }
    public string SystemId { get; set; } = string.Empty;
    public KeyDerivationInfo KeyDerivationInfo { get; set; } = new();
}

public class KeyDerivationInfo
{
    public string Purpose { get; set; } = string.Empty;
    public string Context { get; set; } = string.Empty;
    public string Algorithm { get; set; } = string.Empty;
    public int OutputLength { get; set; }
}
```

### Encrypted Backup File Handler

```csharp
public class EncryptedBackupWriter
{
    private readonly BackupEncryptionManager _encryptionManager;
    
    public EncryptedBackupWriter(BackupEncryptionManager encryptionManager)
    {
        _encryptionManager = encryptionManager;
    }
    
    /// <summary>
    /// Encrypts and writes backup file
    /// </summary>
    public async Task WriteEncryptedBackupAsync(string backupSetId, string contentPath, 
        Stream sourceData, Stream destinationStream, DataClassification classification)
    {
        var encryptionKey = _encryptionManager.GetContentEncryptionKey(backupSetId, contentPath, classification);
        
        using var aes = Aes.Create();
        aes.Key = encryptionKey;
        aes.GenerateIV();
        
        // Write IV to beginning of encrypted stream
        await destinationStream.WriteAsync(aes.IV);
        
        // Write encrypted content
        using var cryptoStream = new CryptoStream(destinationStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
        await sourceData.CopyToAsync(cryptoStream);
        await cryptoStream.FlushFinalBlockAsync();
    }
    
    /// <summary>
    /// Reads and decrypts backup file
    /// </summary>
    public async Task<Stream> ReadEncryptedBackupAsync(string backupSetId, string contentPath, 
        Stream encryptedStream, DataClassification classification)
    {
        var encryptionKey = _encryptionManager.GetContentEncryptionKey(backupSetId, contentPath, classification);
        
        using var aes = Aes.Create();
        aes.Key = encryptionKey;
        
        // Read IV from beginning of stream
        var iv = new byte[aes.BlockSize / 8];
        await encryptedStream.ReadAsync(iv.AsMemory(0, iv.Length));
        aes.IV = iv;
        
        // Return decrypted stream
        return new CryptoStream(encryptedStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
    }
}
```

### Backup Recovery System

```csharp
public class BackupRecoveryManager
{
    private readonly BackupEncryptionManager _encryptionManager;
    
    public BackupRecoveryManager(BackupEncryptionManager encryptionManager)
    {
        _encryptionManager = encryptionManager;
    }
    
    /// <summary>
    /// Recovers encryption key from backup metadata
    /// </summary>
    public byte[] RecoverEncryptionKey(BackupMetadata metadata, byte[] archiveMasterKey)
    {
        // Recreate the encryption manager with the master key
        var recoveryManager = new BackupEncryptionManager(archiveMasterKey, metadata.SystemId);
        
        // Parse the stored context
        var contextBytes = Convert.FromBase64String(metadata.KeyDerivationInfo.Context);
        
        // Recreate the key using stored derivation parameters
        return SecureKeyDerivation.DeriveKey(
            masterKey: archiveMasterKey,
            purpose: metadata.KeyDerivationInfo.Purpose,
            outputLength: metadata.KeyDerivationInfo.OutputLength,
            context: contextBytes
        );
    }
    
    /// <summary>
    /// Validates backup integrity and recoverability
    /// </summary>
    public async Task<BackupValidationResult> ValidateBackupRecoverabilityAsync(
        BackupMetadata metadata, Stream testDataStream)
    {
        try
        {
            // Test if we can derive the expected key
            var testKey = RecoverEncryptionKey(metadata, _encryptionManager._archiveMasterKey);
            
            if (testKey.Length != metadata.KeyDerivationInfo.OutputLength)
            {
                return BackupValidationResult.Failed("Key derivation produced incorrect length");
            }
            
            // Test encryption/decryption round trip
            using var testMemoryStream = new MemoryStream();
            var writer = new EncryptedBackupWriter(_encryptionManager);
            
            await writer.WriteEncryptedBackupAsync(
                metadata.BackupSetId, 
                "test-file", 
                testDataStream, 
                testMemoryStream, 
                DataClassification.Internal
            );
            
            testMemoryStream.Position = 0;
            using var decryptedStream = await writer.ReadEncryptedBackupAsync(
                metadata.BackupSetId, 
                "test-file", 
                testMemoryStream, 
                DataClassification.Internal
            );
            
            return BackupValidationResult.Success();
        }
        catch (Exception ex)
        {
            return BackupValidationResult.Failed($"Validation failed: {ex.Message}");
        }
    }
}

public class BackupValidationResult
{
    public bool IsValid { get; private set; }
    public string? ErrorMessage { get; private set; }
    
    public static BackupValidationResult Success() => new() { IsValid = true };
    public static BackupValidationResult Failed(string error) => new() { IsValid = false, ErrorMessage = error };
}
```

### Enterprise Backup Orchestrator

```csharp
public class EnterpriseBackupOrchestrator
{
    private readonly BackupEncryptionManager _encryptionManager;
    private readonly IBackupStorage _storage;
    private readonly ILogger<EnterpriseBackupOrchestrator> _logger;
    
    public EnterpriseBackupOrchestrator(
        BackupEncryptionManager encryptionManager,
        IBackupStorage storage,
        ILogger<EnterpriseBackupOrchestrator> logger)
    {
        _encryptionManager = encryptionManager;
        _storage = storage;
        _logger = logger;
    }
    
    /// <summary>
    /// Performs a complete backup operation with encryption
    /// </summary>
    public async Task<BackupResult> PerformBackupAsync(BackupRequest request)
    {
        var backupSetId = GenerateBackupSetId();
        var metadata = _encryptionManager.CreateBackupMetadata(backupSetId, request.BackupType, DateTimeOffset.UtcNow);
        
        _logger.LogInformation("Starting {BackupType} backup {BackupSetId}", request.BackupType, backupSetId);
        
        var encryptedFiles = new List<EncryptedFileInfo>();
        var writer = new EncryptedBackupWriter(_encryptionManager);
        
        foreach (var sourceFile in request.SourceFiles)
        {
            try
            {
                using var sourceStream = File.OpenRead(sourceFile.Path);
                using var destinationStream = await _storage.CreateBackupFileAsync(backupSetId, sourceFile.RelativePath);
                
                await writer.WriteEncryptedBackupAsync(
                    backupSetId,
                    sourceFile.RelativePath,
                    sourceStream,
                    destinationStream,
                    sourceFile.Classification
                );
                
                encryptedFiles.Add(new EncryptedFileInfo
                {
                    RelativePath = sourceFile.RelativePath,
                    Classification = sourceFile.Classification,
                    OriginalSize = sourceStream.Length,
                    EncryptedSize = destinationStream.Length
                });
                
                _logger.LogDebug("Encrypted file {FilePath} ({OriginalSize} bytes)", 
                    sourceFile.RelativePath, sourceStream.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to encrypt file {FilePath}", sourceFile.Path);
                throw;
            }
        }
        
        // Store backup metadata
        await _storage.StoreBackupMetadataAsync(backupSetId, metadata);
        
        _logger.LogInformation("Completed backup {BackupSetId} with {FileCount} files", 
            backupSetId, encryptedFiles.Count);
        
        return new BackupResult
        {
            BackupSetId = backupSetId,
            Metadata = metadata,
            EncryptedFiles = encryptedFiles,
            IsSuccess = true
        };
    }
    
    /// <summary>
    /// Restores files from encrypted backup
    /// </summary>
    public async Task<RestoreResult> RestoreBackupAsync(string backupSetId, string destinationPath)
    {
        _logger.LogInformation("Starting restore of backup {BackupSetId} to {DestinationPath}", 
            backupSetId, destinationPath);
        
        var metadata = await _storage.GetBackupMetadataAsync(backupSetId);
        var fileList = await _storage.GetBackupFileListAsync(backupSetId);
        
        var writer = new EncryptedBackupWriter(_encryptionManager);
        var restoredFiles = new List<string>();
        
        foreach (var fileInfo in fileList)
        {
            try
            {
                var destinationFilePath = Path.Combine(destinationPath, fileInfo.RelativePath);
                Directory.CreateDirectory(Path.GetDirectoryName(destinationFilePath)!);
                
                using var encryptedStream = await _storage.OpenBackupFileAsync(backupSetId, fileInfo.RelativePath);
                using var decryptedStream = await writer.ReadEncryptedBackupAsync(
                    backupSetId, 
                    fileInfo.RelativePath, 
                    encryptedStream, 
                    fileInfo.Classification
                );
                using var fileStream = File.Create(destinationFilePath);
                
                await decryptedStream.CopyToAsync(fileStream);
                restoredFiles.Add(destinationFilePath);
                
                _logger.LogDebug("Restored file {FilePath}", destinationFilePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to restore file {FilePath}", fileInfo.RelativePath);
                throw;
            }
        }
        
        _logger.LogInformation("Completed restore of backup {BackupSetId} with {FileCount} files", 
            backupSetId, restoredFiles.Count);
        
        return new RestoreResult
        {
            BackupSetId = backupSetId,
            RestoredFiles = restoredFiles,
            IsSuccess = true
        };
    }
    
    private string GenerateBackupSetId()
    {
        return $"{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}"[..24];
    }
}

// Supporting classes and interfaces
public interface IBackupStorage
{
    Task<Stream> CreateBackupFileAsync(string backupSetId, string relativePath);
    Task<Stream> OpenBackupFileAsync(string backupSetId, string relativePath);
    Task StoreBackupMetadataAsync(string backupSetId, BackupMetadata metadata);
    Task<BackupMetadata> GetBackupMetadataAsync(string backupSetId);
    Task<List<FileInfo>> GetBackupFileListAsync(string backupSetId);
}

public class BackupRequest
{
    public BackupType BackupType { get; set; }
    public List<SourceFileInfo> SourceFiles { get; set; } = new();
}

public class SourceFileInfo
{
    public string Path { get; set; } = string.Empty;
    public string RelativePath { get; set; } = string.Empty;
    public DataClassification Classification { get; set; }
}

public class EncryptedFileInfo
{
    public string RelativePath { get; set; } = string.Empty;
    public DataClassification Classification { get; set; }
    public long OriginalSize { get; set; }
    public long EncryptedSize { get; set; }
}

public class BackupResult
{
    public string BackupSetId { get; set; } = string.Empty;
    public BackupMetadata Metadata { get; set; } = new();
    public List<EncryptedFileInfo> EncryptedFiles { get; set; } = new();
    public bool IsSuccess { get; set; }
}

public class RestoreResult
{
    public string BackupSetId { get; set; } = string.Empty;
    public List<string> RestoredFiles { get; set; } = new();
    public bool IsSuccess { get; set; }
}
```

## Security Considerations

### ✅ Best Practices

1. **Master Key Escrow**: Store archive master key in multiple secure locations
2. **Key Recovery Testing**: Regularly test key recovery procedures
3. **Metadata Protection**: Encrypt backup metadata with different keys than content
4. **Retention Compliance**: Ensure keys remain available for full retention period
5. **Access Logging**: Log all backup encryption and decryption operations

### ⚠️ Important Warnings

1. **Master Key Loss**: Loss of archive master key means permanent data loss
2. **Time Synchronization**: Backup date context must be consistent across systems
3. **Storage Security**: Backup storage must be as secure as production systems
4. **Key Rotation**: Plan for archive master key rotation without losing old backups
5. **Disaster Recovery**: Test complete recovery scenarios including key recovery

## Compliance Features

```csharp
public class ComplianceBackupManager : BackupEncryptionManager
{
    private readonly IComplianceLogger _complianceLogger;
    
    public ComplianceBackupManager(byte[] archiveMasterKey, string backupSystemId, IComplianceLogger complianceLogger)
        : base(archiveMasterKey, backupSystemId)
    {
        _complianceLogger = complianceLogger;
    }
    
    public override byte[] GetContentEncryptionKey(string backupSetId, string contentPath, DataClassification classification)
    {
        var key = base.GetContentEncryptionKey(backupSetId, contentPath, classification);
        
        _complianceLogger.LogKeyDerivation(new KeyDerivationEvent
        {
            BackupSetId = backupSetId,
            ContentPath = contentPath,
            Classification = classification,
            Timestamp = DateTimeOffset.UtcNow,
            Operation = "key_derivation"
        });
        
        return key;
    }
}

public interface IComplianceLogger
{
    void LogKeyDerivation(KeyDerivationEvent eventInfo);
}

public class KeyDerivationEvent
{
    public string BackupSetId { get; set; } = string.Empty;
    public string ContentPath { get; set; } = string.Empty;
    public DataClassification Classification { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public string Operation { get; set; } = string.Empty;
}
```

## Testing

```csharp
[Test]
public void BackupKeys_ShouldBeDeterministic()
{
    var manager = new BackupEncryptionManager(TestArchiveKey, "test-system");
    var backupDate = DateTimeOffset.Parse("2023-01-01T12:00:00Z");
    
    var key1 = manager.GetBackupGenerationKey(BackupType.Full, backupDate, "backup-001");
    var key2 = manager.GetBackupGenerationKey(BackupType.Full, backupDate, "backup-001");
    
    Assert.That(key1, Is.EqualTo(key2));
}

[Test]
public void DifferentBackupSets_ShouldHaveDifferentKeys()
{
    var manager = new BackupEncryptionManager(TestArchiveKey, "test-system");
    var backupDate = DateTimeOffset.Parse("2023-01-01T12:00:00Z");
    
    var key1 = manager.GetBackupGenerationKey(BackupType.Full, backupDate, "backup-001");
    var key2 = manager.GetBackupGenerationKey(BackupType.Full, backupDate, "backup-002");
    
    Assert.That(key1, Is.Not.EqualTo(key2));
}
```

## Common Pitfalls

1. **Master key loss**: Implement proper key escrow and recovery procedures
2. **Inconsistent contexts**: Maintain consistent backup set ID and path formats
3. **Clock skew**: Ensure consistent time sources for backup date contexts
4. **Metadata corruption**: Protect backup metadata as carefully as backup data
5. **Recovery testing**: Regularly test full recovery procedures including key recovery