# Session Key Management

## Problem Description

Web applications and APIs need to generate unique session keys that provide:
- Session isolation between different users
- Forward secrecy (old sessions can't be decrypted if current keys are compromised)
- Efficient key derivation without storing individual session keys
- Support for different types of session-specific cryptographic material

## Security Requirements

- Each session must have unique cryptographic keys
- Session keys should not be predictable or enumerable
- Multiple key types per session (encryption, authentication, CSRF protection)
- Time-based session expiration support
- Ability to invalidate all sessions if master key is rotated

## Recommended Solution

Use KDF with session-specific context data including user ID, session ID, and timestamp.

### Parameters

- **Master Key**: 256-bit application master key (rotated periodically)
- **Purpose**: Session key type ("session-encryption", "session-auth", "csrf-token")
- **Context**: User ID + Session ID + Timestamp (if time-based rotation needed)
- **Output Length**: 32 bytes (sufficient for most symmetric algorithms)

## Code Example

```csharp
using Kdf108.Simple;
using System.Security.Cryptography;

public class SessionKeyManager
{
    private readonly byte[] _masterKey;
    
    public SessionKeyManager(byte[] masterKey)
    {
        _masterKey = masterKey ?? throw new ArgumentNullException(nameof(masterKey));
    }
    
    /// <summary>
    /// Generates a new session with unique ID and derives initial keys
    /// </summary>
    public SessionKeys CreateSession(string userId)
    {
        if (string.IsNullOrEmpty(userId))
            throw new ArgumentException("User ID cannot be null or empty", nameof(userId));
            
        // Generate unique session ID
        var sessionId = GenerateSessionId();
        
        return new SessionKeys
        {
            SessionId = sessionId,
            UserId = userId,
            EncryptionKey = GetSessionEncryptionKey(userId, sessionId),
            AuthenticationKey = GetSessionAuthenticationKey(userId, sessionId),
            CsrfToken = GetCsrfToken(userId, sessionId)
        };
    }
    
    /// <summary>
    /// Derives session encryption key
    /// </summary>
    public byte[] GetSessionEncryptionKey(string userId, string sessionId)
    {
        var context = BuildSessionContext(userId, sessionId);
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _masterKey,
            purpose: "session-encryption-v1",
            outputLength: 32,
            context: context
        );
    }
    
    /// <summary>
    /// Derives session authentication key (for HMACs, etc.)
    /// </summary>
    public byte[] GetSessionAuthenticationKey(string userId, string sessionId)
    {
        var context = BuildSessionContext(userId, sessionId);
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _masterKey,
            purpose: "session-auth-v1",
            outputLength: 32,
            context: context
        );
    }
    
    /// <summary>
    /// Generates CSRF protection token
    /// </summary>
    public string GetCsrfToken(string userId, string sessionId)
    {
        var context = BuildSessionContext(userId, sessionId);
        
        var tokenBytes = SecureKeyDerivation.DeriveKey(
            masterKey: _masterKey,
            purpose: "csrf-token-v1",
            outputLength: 32,
            context: context
        );
        
        return Convert.ToBase64String(tokenBytes);
    }
    
    private byte[] BuildSessionContext(string userId, string sessionId)
    {
        var contextString = $"user-{userId}-session-{sessionId}";
        return System.Text.Encoding.UTF8.GetBytes(contextString);
    }
    
    private string GenerateSessionId()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }
}

public class SessionKeys
{
    public string SessionId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public byte[] EncryptionKey { get; set; } = Array.Empty<byte>();
    public byte[] AuthenticationKey { get; set; } = Array.Empty<byte>();
    public string CsrfToken { get; set; } = string.Empty;
}
```

## Advanced Time-Based Sessions

For applications requiring time-based key rotation:

```csharp
public class TimeBoundSessionKeyManager : SessionKeyManager
{
    private readonly TimeSpan _keyRotationInterval;
    
    public TimeBoundSessionKeyManager(byte[] masterKey, TimeSpan keyRotationInterval) 
        : base(masterKey)
    {
        _keyRotationInterval = keyRotationInterval;
    }
    
    /// <summary>
    /// Gets encryption key for specific time period
    /// </summary>
    public byte[] GetTimeBasedEncryptionKey(string userId, string sessionId, DateTimeOffset timestamp)
    {
        var timePeriod = GetTimePeriod(timestamp);
        var context = BuildTimeBoundContext(userId, sessionId, timePeriod);
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _masterKey,
            purpose: "session-encryption-timed-v1",
            outputLength: 32,
            context: context
        );
    }
    
    private long GetTimePeriod(DateTimeOffset timestamp)
    {
        // Round down to nearest rotation interval
        var ticks = timestamp.Ticks;
        var intervalTicks = _keyRotationInterval.Ticks;
        return ticks / intervalTicks;
    }
    
    private byte[] BuildTimeBoundContext(string userId, string sessionId, long timePeriod)
    {
        var contextString = $"user-{userId}-session-{sessionId}-period-{timePeriod}";
        return System.Text.Encoding.UTF8.GetBytes(contextString);
    }
}
```

## Integration Example

```csharp
// In your web application startup
services.AddSingleton<SessionKeyManager>(provider =>
{
    var masterKey = GetMasterKeyFromSecureStorage(); // Your secure key storage
    return new SessionKeyManager(masterKey);
});

// In your authentication controller
[HttpPost("login")]
public IActionResult Login([FromBody] LoginRequest request)
{
    if (ValidateCredentials(request.Username, request.Password))
    {
        var sessionKeys = _sessionKeyManager.CreateSession(request.Username);
        
        // Store session ID in secure cookie
        Response.Cookies.Append("SessionId", sessionKeys.SessionId, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            MaxAge = TimeSpan.FromHours(8)
        });
        
        return Ok(new { CsrfToken = sessionKeys.CsrfToken });
    }
    
    return Unauthorized();
}

// In your protected endpoints
[HttpPost("protected-action")]
public IActionResult ProtectedAction([FromHeader] string csrfToken)
{
    var sessionId = Request.Cookies["SessionId"];
    var userId = GetCurrentUserId(); // Your user identification logic
    
    // Verify CSRF token
    var expectedToken = _sessionKeyManager.GetCsrfToken(userId, sessionId);
    if (expectedToken != csrfToken)
    {
        return BadRequest("Invalid CSRF token");
    }
    
    // Use session keys for encrypting sensitive data
    var encryptionKey = _sessionKeyManager.GetSessionEncryptionKey(userId, sessionId);
    // ... encrypt sensitive response data
    
    return Ok();
}
```

## Security Considerations

### ✅ Best Practices

1. **Session ID Randomness**: Use cryptographically secure random session IDs
2. **Secure Cookies**: Use HttpOnly, Secure, and SameSite cookie attributes
3. **Session Expiration**: Implement both idle and absolute session timeouts
4. **Key Rotation**: Rotate master keys periodically (requires re-establishing sessions)
5. **Context Uniqueness**: Ensure user ID + session ID combinations are unique

### ⚠️ Important Warnings

1. **Session Fixation**: Always generate new session IDs after authentication
2. **Predictable IDs**: Never use sequential or predictable session identifiers
3. **Master Key Storage**: Protect the master key with same rigor as session data
4. **Time Synchronization**: For time-based keys, ensure server time synchronization
5. **Session Storage**: Don't store derived keys - regenerate them as needed

## Performance Optimizations

### Caching Derived Keys

```csharp
public class CachedSessionKeyManager : SessionKeyManager
{
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _cacheExpiry;
    
    public CachedSessionKeyManager(byte[] masterKey, IMemoryCache cache, TimeSpan cacheExpiry) 
        : base(masterKey)
    {
        _cache = cache;
        _cacheExpiry = cacheExpiry;
    }
    
    public override byte[] GetSessionEncryptionKey(string userId, string sessionId)
    {
        var cacheKey = $"enc:{userId}:{sessionId}";
        
        if (_cache.TryGetValue(cacheKey, out byte[]? cachedKey) && cachedKey != null)
        {
            return cachedKey;
        }
        
        var key = base.GetSessionEncryptionKey(userId, sessionId);
        _cache.Set(cacheKey, key, _cacheExpiry);
        
        return key;
    }
}
```

## Testing

```csharp
[Test]
public void DifferentSessions_ShouldHaveDifferentKeys()
{
    var manager = new SessionKeyManager(TestMasterKey);
    
    var session1 = manager.CreateSession("user1");
    var session2 = manager.CreateSession("user1");
    
    Assert.That(session1.EncryptionKey, Is.Not.EqualTo(session2.EncryptionKey));
    Assert.That(session1.SessionId, Is.Not.EqualTo(session2.SessionId));
}

[Test]
public void SameSession_ShouldHaveConsistentKeys()
{
    var manager = new SessionKeyManager(TestMasterKey);
    
    var key1 = manager.GetSessionEncryptionKey("user1", "session123");
    var key2 = manager.GetSessionEncryptionKey("user1", "session123");
    
    Assert.That(key1, Is.EqualTo(key2));
}
```

## Common Pitfalls

1. **Storing derived keys**: Regenerate keys from session context instead of storing them
2. **Weak session IDs**: Use proper random number generation, not GUIDs or timestamps
3. **Missing CSRF protection**: Always implement CSRF tokens for state-changing operations
4. **Session hijacking**: Use HTTPS and secure cookie settings in production
5. **Memory leaks**: Clear sensitive key material from memory after use