# KDF Usage Scenarios

This directory contains practical examples and use cases for the KDF-108 library, showing how to apply key derivation functions in real-world scenarios.

## Available Scenarios

- [Multi-Tenant Applications](multi-tenant.md) - Key separation for multi-tenant systems
- [Session Management](session-management.md) - Deriving session-specific keys
- [Database Encryption](database-encryption.md) - Key management for encrypted databases
- [API Authentication](api-authentication.md) - Token generation and key derivation
- [Backup Systems](backup-encryption.md) - Long-term backup encryption strategies

Each scenario includes:
- Problem description and security requirements
- Recommended parameters and configurations
- Complete code examples
- Security considerations and best practices
- Common pitfalls to avoid

## How to Use These Scenarios

1. Identify your use case from the available scenarios
2. Review the security requirements and recommendations
3. Adapt the provided examples to your specific needs
4. Test thoroughly in a development environment
5. Consider professional security review for production systems

## Security Notes

⚠️ These scenarios are educational examples. Always:
- Use cryptographically secure random master keys in production
- Implement proper key storage and management
- Follow your organization's security policies
- Consider professional cryptographic review for critical systems