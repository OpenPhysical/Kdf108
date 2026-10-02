# API Authentication Token Generation

## Problem Description

API authentication systems require secure token generation that provides:
- Unique, non-predictable authentication tokens
- Support for different token types (access tokens, refresh tokens, API keys)
- Token validation without database lookups
- Configurable token lifetimes and scopes
- Integration with existing authentication systems

## Security Requirements

- Tokens must be cryptographically secure and non-predictable
- Different token types must be cryptographically isolated
- Token validation should be stateless where possible
- Support for token revocation and rotation
- Audit trail of token generation and usage

## Recommended Solution

Use KDF to derive token signing keys and generate deterministic tokens based on user context and token metadata.

### Parameters

- **Master Key**: 256-bit application signing key
- **Purpose**: Token type ("access-token", "refresh-token", "api-key")
- **Context**: User ID, client ID, token expiration, and scope
- **Output Length**: 32 bytes for HMAC keys, 64 bytes for larger tokens

## Code Example

### Basic API Token Manager

```csharp
using Kdf108.Simple;
using System.Security.Cryptography;
using System.Text.Json;

public class ApiTokenManager
{
    private readonly byte[] _masterKey;
    private readonly string _issuer;
    
    public ApiTokenManager(byte[] masterKey, string issuer)
    {
        _masterKey = masterKey ?? throw new ArgumentNullException(nameof(masterKey));
        _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
    }
    
    /// <summary>
    /// Generates an access token for a user
    /// </summary>
    public AccessToken GenerateAccessToken(string userId, string clientId, TimeSpan lifetime, string[] scopes)
    {
        if (string.IsNullOrEmpty(userId))
            throw new ArgumentException("User ID cannot be null or empty", nameof(userId));
        if (string.IsNullOrEmpty(clientId))
            throw new ArgumentException("Client ID cannot be null or empty", nameof(clientId));
            
        var expiresAt = DateTimeOffset.UtcNow.Add(lifetime);
        var tokenId = GenerateTokenId();
        
        var claims = new TokenClaims
        {
            TokenId = tokenId,
            UserId = userId,
            ClientId = clientId,
            Issuer = _issuer,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt,
            Scopes = scopes
        };
        
        var signingKey = GetTokenSigningKey(userId, clientId, tokenId, "access-token");
        var tokenString = GenerateSignedToken(claims, signingKey);
        
        return new AccessToken
        {
            Token = tokenString,
            ExpiresAt = expiresAt,
            Scopes = scopes
        };
    }
    
    /// <summary>
    /// Generates a refresh token
    /// </summary>
    public RefreshToken GenerateRefreshToken(string userId, string clientId, TimeSpan lifetime)
    {
        var expiresAt = DateTimeOffset.UtcNow.Add(lifetime);
        var tokenId = GenerateTokenId();
        
        var claims = new TokenClaims
        {
            TokenId = tokenId,
            UserId = userId,
            ClientId = clientId,
            Issuer = _issuer,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt,
            TokenType = "refresh"
        };
        
        var signingKey = GetTokenSigningKey(userId, clientId, tokenId, "refresh-token");
        var tokenString = GenerateSignedToken(claims, signingKey);
        
        return new RefreshToken
        {
            Token = tokenString,
            ExpiresAt = expiresAt
        };
    }
    
    /// <summary>
    /// Generates a long-lived API key
    /// </summary>
    public ApiKey GenerateApiKey(string userId, string keyName, string[] scopes, TimeSpan? lifetime = null)
    {
        var expiresAt = lifetime.HasValue ? DateTimeOffset.UtcNow.Add(lifetime.Value) : (DateTimeOffset?)null;
        var tokenId = GenerateTokenId();
        
        var claims = new TokenClaims
        {
            TokenId = tokenId,
            UserId = userId,
            ClientId = keyName, // Use key name as client ID for API keys
            Issuer = _issuer,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt,
            Scopes = scopes,
            TokenType = "api-key"
        };
        
        var signingKey = GetTokenSigningKey(userId, keyName, tokenId, "api-key");
        var tokenString = GenerateSignedToken(claims, signingKey);
        
        return new ApiKey
        {
            KeyId = tokenId,
            Token = tokenString,
            Name = keyName,
            ExpiresAt = expiresAt,
            Scopes = scopes
        };
    }
    
    /// <summary>
    /// Validates and parses a token
    /// </summary>
    public TokenValidationResult ValidateToken(string token, string expectedTokenType)
    {
        try
        {
            var (claims, signature) = ParseToken(token);
            
            // Check expiration
            if (claims.ExpiresAt.HasValue && claims.ExpiresAt.Value <= DateTimeOffset.UtcNow)
            {
                return TokenValidationResult.Expired();
            }
            
            // Check token type
            var tokenType = claims.TokenType ?? "access-token";
            if (tokenType != expectedTokenType)
            {
                return TokenValidationResult.Invalid("Invalid token type");
            }
            
            // Regenerate signing key and verify signature
            var signingKey = GetTokenSigningKey(claims.UserId, claims.ClientId, claims.TokenId, tokenType);
            var expectedSignature = ComputeTokenSignature(claims, signingKey);
            
            if (!signature.SequenceEqual(expectedSignature))
            {
                return TokenValidationResult.Invalid("Invalid signature");
            }
            
            return TokenValidationResult.Valid(claims);
        }
        catch (Exception ex)
        {
            return TokenValidationResult.Invalid($"Token parsing error: {ex.Message}");
        }
    }
    
    private byte[] GetTokenSigningKey(string userId, string clientId, string tokenId, string tokenType)
    {
        var context = BuildTokenContext(userId, clientId, tokenId);
        
        return SecureKeyDerivation.DeriveKey(
            masterKey: _masterKey,
            purpose: $"{tokenType}-signing-v1",
            outputLength: 32,
            context: context
        );
    }
    
    private byte[] BuildTokenContext(string userId, string clientId, string tokenId)
    {
        var contextString = $"user-{userId}-client-{clientId}-token-{tokenId}";
        return System.Text.Encoding.UTF8.GetBytes(contextString);
    }
    
    private string GenerateSignedToken(TokenClaims claims, byte[] signingKey)
    {
        var claimsJson = JsonSerializer.Serialize(claims);
        var claimsBytes = System.Text.Encoding.UTF8.GetBytes(claimsJson);
        var claimsB64 = Convert.ToBase64String(claimsBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        
        var signature = ComputeTokenSignature(claims, signingKey);
        var signatureB64 = Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        
        return $"{claimsB64}.{signatureB64}";
    }
    
    private byte[] ComputeTokenSignature(TokenClaims claims, byte[] signingKey)
    {
        var claimsJson = JsonSerializer.Serialize(claims);
        var claimsBytes = System.Text.Encoding.UTF8.GetBytes(claimsJson);
        
        using var hmac = new HMACSHA256(signingKey);
        return hmac.ComputeHash(claimsBytes);
    }
    
    private (TokenClaims claims, byte[] signature) ParseToken(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 2)
            throw new ArgumentException("Invalid token format");
            
        var claimsB64 = parts[0].Replace('-', '+').Replace('_', '/');
        claimsB64 += new string('=', (4 - claimsB64.Length % 4) % 4); // Add padding
        
        var signatureB64 = parts[1].Replace('-', '+').Replace('_', '/');
        signatureB64 += new string('=', (4 - signatureB64.Length % 4) % 4); // Add padding
        
        var claimsBytes = Convert.FromBase64String(claimsB64);
        var claimsJson = System.Text.Encoding.UTF8.GetString(claimsBytes);
        var claims = JsonSerializer.Deserialize<TokenClaims>(claimsJson) 
                     ?? throw new ArgumentException("Invalid token claims");
                     
        var signature = Convert.FromBase64String(signatureB64);
        
        return (claims, signature);
    }
    
    private string GenerateTokenId()
    {
        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

// Supporting classes
public class TokenClaims
{
    public string TokenId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTimeOffset IssuedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public string[] Scopes { get; set; } = Array.Empty<string>();
    public string? TokenType { get; set; }
}

public class AccessToken
{
    public string Token { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
    public string[] Scopes { get; set; } = Array.Empty<string>();
}

public class RefreshToken
{
    public string Token { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
}

public class ApiKey
{
    public string KeyId { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public DateTimeOffset? ExpiresAt { get; set; }
    public string[] Scopes { get; set; } = Array.Empty<string>();
}

public class TokenValidationResult
{
    public bool IsValid { get; private set; }
    public bool IsExpired { get; private set; }
    public string? ErrorMessage { get; private set; }
    public TokenClaims? Claims { get; private set; }
    
    public static TokenValidationResult Valid(TokenClaims claims) => new()
    {
        IsValid = true,
        Claims = claims
    };
    
    public static TokenValidationResult Invalid(string error) => new()
    {
        IsValid = false,
        ErrorMessage = error
    };
    
    public static TokenValidationResult Expired() => new()
    {
        IsValid = false,
        IsExpired = true,
        ErrorMessage = "Token has expired"
    };
}
```

### Integration with ASP.NET Core

```csharp
// Startup configuration
public void ConfigureServices(IServiceCollection services)
{
    services.AddSingleton<ApiTokenManager>(provider =>
    {
        var masterKey = GetTokenSigningKey(); // Your secure key retrieval
        return new ApiTokenManager(masterKey, "your-api-issuer");
    });
    
    services.AddAuthentication("CustomToken")
        .AddScheme<CustomTokenAuthenticationSchemeOptions, CustomTokenAuthenticationHandler>(
            "CustomToken", options => { });
}

// Authentication handler
public class CustomTokenAuthenticationHandler : AuthenticationHandler<CustomTokenAuthenticationSchemeOptions>
{
    private readonly ApiTokenManager _tokenManager;
    
    public CustomTokenAuthenticationHandler(
        IOptionsMonitor<CustomTokenAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        ApiTokenManager tokenManager)
        : base(options, logger, encoder, clock)
    {
        _tokenManager = tokenManager;
    }
    
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.ContainsKey("Authorization"))
        {
            return Task.FromResult(AuthenticateResult.Fail("Missing Authorization header"));
        }
        
        var authHeader = Request.Headers["Authorization"].ToString();
        if (!authHeader.StartsWith("Bearer "))
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid Authorization header format"));
        }
        
        var token = authHeader.Substring("Bearer ".Length).Trim();
        var validationResult = _tokenManager.ValidateToken(token, "access-token");
        
        if (!validationResult.IsValid)
        {
            var message = validationResult.IsExpired ? "Token expired" : validationResult.ErrorMessage;
            return Task.FromResult(AuthenticateResult.Fail(message!));
        }
        
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, validationResult.Claims!.UserId),
            new Claim("client_id", validationResult.Claims.ClientId),
            new Claim("token_id", validationResult.Claims.TokenId)
        };
        
        // Add scope claims
        foreach (var scope in validationResult.Claims.Scopes)
        {
            claims = claims.Append(new Claim("scope", scope)).ToArray();
        }
        
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

// Token endpoint controller
[ApiController]
[Route("api/[controller]")]
public class TokenController : ControllerBase
{
    private readonly ApiTokenManager _tokenManager;
    
    public TokenController(ApiTokenManager tokenManager)
    {
        _tokenManager = tokenManager;
    }
    
    [HttpPost("access")]
    public IActionResult CreateAccessToken([FromBody] AccessTokenRequest request)
    {
        // Validate client credentials (implementation dependent)
        if (!ValidateClientCredentials(request.ClientId, request.ClientSecret))
        {
            return Unauthorized();
        }
        
        var accessToken = _tokenManager.GenerateAccessToken(
            request.UserId, 
            request.ClientId, 
            TimeSpan.FromHours(1), 
            request.Scopes
        );
        
        var refreshToken = _tokenManager.GenerateRefreshToken(
            request.UserId, 
            request.ClientId, 
            TimeSpan.FromDays(30)
        );
        
        return Ok(new
        {
            access_token = accessToken.Token,
            refresh_token = refreshToken.Token,
            expires_in = (int)TimeSpan.FromHours(1).TotalSeconds,
            token_type = "Bearer",
            scope = string.Join(" ", request.Scopes)
        });
    }
    
    [HttpPost("api-key")]
    [Authorize] // Requires existing authentication
    public IActionResult CreateApiKey([FromBody] ApiKeyRequest request)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }
        
        var apiKey = _tokenManager.GenerateApiKey(
            userId, 
            request.Name, 
            request.Scopes, 
            request.Lifetime
        );
        
        return Ok(new
        {
            key_id = apiKey.KeyId,
            api_key = apiKey.Token,
            name = apiKey.Name,
            expires_at = apiKey.ExpiresAt,
            scopes = apiKey.Scopes
        });
    }
    
    private bool ValidateClientCredentials(string clientId, string clientSecret)
    {
        // Implement your client validation logic
        return true; // Placeholder
    }
}
```

## Advanced Features

### Token Revocation

```csharp
public class TokenRevocationManager
{
    private readonly IMemoryCache _revokedTokens;
    private readonly ApiTokenManager _tokenManager;
    
    public TokenRevocationManager(ApiTokenManager tokenManager, IMemoryCache cache)
    {
        _tokenManager = tokenManager;
        _revokedTokens = cache;
    }
    
    public void RevokeToken(string token)
    {
        var validationResult = _tokenManager.ValidateToken(token, "access-token");
        if (validationResult.IsValid && validationResult.Claims != null)
        {
            var expiresAt = validationResult.Claims.ExpiresAt ?? DateTimeOffset.UtcNow.AddDays(1);
            _revokedTokens.Set($"revoked:{validationResult.Claims.TokenId}", true, expiresAt);
        }
    }
    
    public bool IsTokenRevoked(string tokenId)
    {
        return _revokedTokens.TryGetValue($"revoked:{tokenId}", out _);
    }
}
```

## Security Considerations

### ✅ Best Practices

1. **Secure Master Key**: Store signing key in HSM or secure key management
2. **Token Lifetimes**: Use short lifetimes for access tokens, longer for refresh tokens
3. **Scope Validation**: Always validate token scopes against requested resources
4. **HTTPS Only**: Never transmit tokens over unencrypted connections
5. **Audit Logging**: Log all token generation and validation events

### ⚠️ Important Warnings

1. **Token Storage**: Never store tokens in localStorage; use secure, HttpOnly cookies
2. **Master Key Rotation**: Plan for signing key rotation without invalidating all tokens
3. **Replay Attacks**: Consider implementing token replay protection for sensitive operations
4. **Client Secrets**: Protect client secrets with same rigor as signing keys
5. **Token Leakage**: Implement token revocation for compromised tokens

## Testing

```csharp
[Test]
public void GeneratedTokens_ShouldBeValid()
{
    var manager = new ApiTokenManager(TestMasterKey, "test-issuer");
    
    var token = manager.GenerateAccessToken("user123", "client456", TimeSpan.FromHours(1), new[] { "read", "write" });
    var validation = manager.ValidateToken(token.Token, "access-token");
    
    Assert.That(validation.IsValid, Is.True);
    Assert.That(validation.Claims?.UserId, Is.EqualTo("user123"));
    Assert.That(validation.Claims?.Scopes, Contains.Item("read"));
}

[Test]
public void ExpiredTokens_ShouldBeInvalid()
{
    var manager = new ApiTokenManager(TestMasterKey, "test-issuer");
    
    var token = manager.GenerateAccessToken("user123", "client456", TimeSpan.FromMilliseconds(-1), new[] { "read" });
    Thread.Sleep(10); // Ensure expiration
    
    var validation = manager.ValidateToken(token.Token, "access-token");
    
    Assert.That(validation.IsValid, Is.False);
    Assert.That(validation.IsExpired, Is.True);
}
```

## Common Pitfalls

1. **Hardcoded secrets**: Never embed signing keys in source code
2. **Insufficient validation**: Always validate token signatures and expiration
3. **Scope creep**: Be specific about token scopes and validate them strictly
4. **Cross-purpose tokens**: Don't use access tokens for refresh operations
5. **Timing attacks**: Use constant-time comparison for signature validation