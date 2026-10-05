// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Internal;
using Org.BouncyCastle.Utilities;

namespace Kdf108.Domain.Sp80056A;

/// <summary>
/// Represents an immutable shared secret resulting from a key agreement operation.
/// </summary>
public sealed class SharedSecret : IEquatable<SharedSecret>, IDisposable
{
    private readonly byte[] _value;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SharedSecret"/> class.
    /// </summary>
    /// <param name="value">The shared secret bytes.</param>
    /// <exception cref="ArgumentNullException">Thrown when value is null.</exception>
    /// <exception cref="ArgumentException">Thrown when value is empty.</exception>
    public SharedSecret(byte[] value)
    {
        if (value == null) throw new ArgumentNullException(nameof(value));
        if (value.Length == 0) throw new ArgumentException("Shared secret cannot be empty", nameof(value));
        
        // Make defensive copy
        _value = new byte[value.Length];
        Array.Copy(value, _value, value.Length);
    }

    /// <summary>
    /// Gets the shared secret value as a new array (defensive copy).
    /// </summary>
    /// <returns>A copy of the shared secret bytes.</returns>
    public byte[] ToArray()
    {
        ThrowIfDisposed();
        var result = new byte[_value.Length];
        Array.Copy(_value, result, _value.Length);
        return result;
    }

    /// <summary>
    /// Gets the shared secret value as a read-only span for zero-copy scenarios.
    /// </summary>
    /// <returns>A read-only span over the shared secret bytes.</returns>
    public ReadOnlySpan<byte> AsSpan()
    {
        ThrowIfDisposed();
        return _value.AsSpan();
    }

    /// <summary>
    /// Gets the length of the shared secret in bytes.
    /// </summary>
    public int Length
    {
        get
        {
            ThrowIfDisposed();
            return _value.Length;
        }
    }

    /// <summary>
    /// Concatenates two shared secrets.
    /// </summary>
    /// <param name="first">The first shared secret.</param>
    /// <param name="second">The second shared secret.</param>
    /// <returns>A new shared secret containing first || second.</returns>
    public static SharedSecret Concatenate(SharedSecret first, SharedSecret second)
    {
        if (first == null) throw new ArgumentNullException(nameof(first));
        if (second == null) throw new ArgumentNullException(nameof(second));
        
        var combined = new byte[first.Length + second.Length];
        first.AsSpan().CopyTo(combined.AsSpan(0, first.Length));
        second.AsSpan().CopyTo(combined.AsSpan(first.Length, second.Length));
        
        try
        {
            return new SharedSecret(combined);
        }
        finally
        {
            SecureMemory.Clear(combined);
        }
    }

    /// <summary>
    /// Determines whether the specified <see cref="SharedSecret"/> is equal to the current shared secret.
    /// </summary>
    /// <param name="other">The shared secret to compare with the current shared secret.</param>
    /// <returns>true if the specified shared secret is equal to the current shared secret; otherwise, false.</returns>
    public bool Equals(SharedSecret? other)
    {
        ThrowIfDisposed();
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;

        other.ThrowIfDisposed();
        return Arrays.FixedTimeEquals(_value, other._value);
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current shared secret.
    /// </summary>
    /// <param name="obj">The object to compare with the current shared secret.</param>
    /// <returns>true if the specified object is equal to the current shared secret; otherwise, false.</returns>
    public override bool Equals(object? obj) => Equals(obj as SharedSecret);

    /// <summary>
    /// Serves as the default hash function.
    /// </summary>
    /// <returns>A hash code for the current shared secret.</returns>
    public override int GetHashCode()
    {
        ThrowIfDisposed();
        // Simple hash combining first few bytes and length
        var hash = new HashCode();
        hash.Add(_value.Length);
        
        // Include up to first 8 bytes in hash
        var bytesToHash = Math.Min(8, _value.Length);
        for (var i = 0; i < bytesToHash; i++)
        {
            hash.Add(_value[i]);
        }
        
        return hash.ToHashCode();
    }

    /// <summary>
    /// Returns a string representation of this shared secret.
    /// Note: Does not expose the actual secret value for security.
    /// </summary>
    /// <returns>A string representation of this shared secret.</returns>
    public override string ToString() => _disposed ? "SharedSecret[disposed]" : $"SharedSecret[{_value.Length} bytes]";

    /// <summary>Erases the owned copy of the shared secret and prevents further use.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        SecureMemory.Clear(_value);
        _disposed = true;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
