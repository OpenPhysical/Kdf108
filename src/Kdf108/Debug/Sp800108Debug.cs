// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#if DEBUG

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Kdf108.Domain.Kdf;
using Microsoft.Extensions.Logging;

namespace Kdf108.Debug;

/// <summary>
/// Debug utilities for SP 800-108 KDF operations.
/// Only available in DEBUG builds.
/// </summary>
public static class Sp800108Debug
{
    private static readonly object s_lock = new();
    private static readonly List<KdfDebugInfo> s_operationHistory = new();
    private static bool s_traceEnabled = false;

    /// <summary>
    /// Gets or sets whether cryptographic tracing is enabled.
    /// </summary>
    public static bool IsCryptographicTracingEnabled
    {
        get => s_traceEnabled;
        set => s_traceEnabled = value;
    }

    /// <summary>
    /// Gets the intermediate values from a KDF operation for debugging.
    /// </summary>
    /// <param name="kdk">The key derivation key.</param>
    /// <param name="label">The label used.</param>
    /// <param name="context">The context used.</param>
    /// <param name="outputLengthBits">The output length in bits.</param>
    /// <param name="options">The KDF options.</param>
    /// <returns>A string containing detailed intermediate values.</returns>
    public static string GetIntermediateValues(
        byte[] kdk,
        string label,
        byte[] context,
        long outputLengthBits,
        KdfOptions options)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== SP 800-108 KDF Debug Information ===");
        sb.AppendLine($"Timestamp: {DateTime.UtcNow:O}");
        sb.AppendLine();
        
        sb.AppendLine("Input Parameters:");
        sb.AppendLine($"  KDK Length: {kdk?.Length ?? 0} bytes");
        sb.AppendLine($"  KDK (hex): {(kdk != null ? Convert.ToHexString(kdk) : "null")}");
        sb.AppendLine($"  Label: '{label}'");
        sb.AppendLine($"  Context Length: {context?.Length ?? 0} bytes");
        sb.AppendLine($"  Context (hex): {(context != null ? Convert.ToHexString(context) : "null")}");
        sb.AppendLine($"  Output Length: {outputLengthBits} bits ({outputLengthBits / 8} bytes)");
        sb.AppendLine();
        
        sb.AppendLine("KDF Options:");
        sb.AppendLine($"  PRF Type: {options.PrfType}");
        sb.AppendLine($"  Counter Length: {options.CounterLengthBits} bits");
        sb.AppendLine($"  Counter Location: {options.CounterLocation}");
        sb.AppendLine($"  Use Counter: {options.UseCounter}");
        sb.AppendLine();

        // Calculate number of iterations
        int prfOutputBits = GetPrfOutputBits(options.PrfType);
        long iterations = (long)Math.Ceiling(outputLengthBits / (double)prfOutputBits);
        sb.AppendLine($"PRF Output Size: {prfOutputBits} bits");
        sb.AppendLine($"Required Iterations: {iterations}");
        
        return sb.ToString();
    }

    /// <summary>
    /// Enables cryptographic tracing with detailed logging.
    /// </summary>
    /// <param name="logger">The logger to use for tracing.</param>
    public static void EnableCryptographicTracing(ILogger logger)
    {
        s_traceEnabled = true;
        logger?.LogDebug("Cryptographic tracing enabled for SP 800-108 operations");
    }

    /// <summary>
    /// Disables cryptographic tracing.
    /// </summary>
    public static void DisableCryptographicTracing()
    {
        s_traceEnabled = false;
    }

    /// <summary>
    /// Gets information about the last KDF operation performed.
    /// </summary>
    /// <returns>Debug information about the last operation, or null if none.</returns>
    public static KdfDebugInfo? GetLastOperationInfo()
    {
        lock (s_lock)
        {
            return s_operationHistory.Count > 0 
                ? s_operationHistory[s_operationHistory.Count - 1] 
                : null;
        }
    }

    /// <summary>
    /// Records debug information about a KDF operation.
    /// </summary>
    internal static void RecordOperation(KdfDebugInfo info)
    {
        if (!s_traceEnabled) return;

        lock (s_lock)
        {
            s_operationHistory.Add(info);
            
            // Keep only last 100 operations to avoid memory issues
            if (s_operationHistory.Count > 100)
            {
                s_operationHistory.RemoveAt(0);
            }
        }
    }

    /// <summary>
    /// Clears the operation history.
    /// </summary>
    public static void ClearHistory()
    {
        lock (s_lock)
        {
            s_operationHistory.Clear();
        }
    }

    /// <summary>
    /// Measures the performance of a KDF operation.
    /// </summary>
    /// <param name="action">The KDF operation to measure.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <param name="logger">Optional logger for output.</param>
    /// <returns>The elapsed time in milliseconds.</returns>
    public static double MeasurePerformance(Action action, string operationName, ILogger? logger = null)
    {
        var sw = Stopwatch.StartNew();
        action();
        sw.Stop();
        
        var elapsed = sw.Elapsed.TotalMilliseconds;
        logger?.LogDebug("KDF operation '{Operation}' completed in {ElapsedMs:F2} ms", 
            operationName, elapsed);
        
        return elapsed;
    }

    private static int GetPrfOutputBits(PrfType prfType)
    {
        return prfType switch
        {
            PrfType.HmacSha1 => 160,
            PrfType.HmacSha224 => 224,
            PrfType.HmacSha256 => 256,
            PrfType.HmacSha384 => 384,
            PrfType.HmacSha512 => 512,
            PrfType.CmacAes128 => 128,
            PrfType.CmacAes192 => 128,
            PrfType.CmacAes256 => 128,
            _ => 256
        };
    }
}

/// <summary>
/// Contains debug information about a KDF operation.
/// </summary>
public class KdfDebugInfo
{
    /// <summary>
    /// Gets or sets the timestamp of the operation.
    /// </summary>
    public DateTime Timestamp { get; set; }

    /// <summary>
    /// Gets or sets the KDF mode used.
    /// </summary>
    public KdfMode Mode { get; set; }

    /// <summary>
    /// Gets or sets the PRF type used.
    /// </summary>
    public PrfType PrfType { get; set; }

    /// <summary>
    /// Gets or sets the output length in bits.
    /// </summary>
    public long OutputLengthBits { get; set; }

    /// <summary>
    /// Gets or sets the number of iterations performed.
    /// </summary>
    public int Iterations { get; set; }

    /// <summary>
    /// Gets or sets the elapsed time in milliseconds.
    /// </summary>
    public double ElapsedMilliseconds { get; set; }

    /// <summary>
    /// Gets or sets any additional notes about the operation.
    /// </summary>
    public string? Notes { get; set; }
}


#endif
