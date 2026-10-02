// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Kdf108.Domain.Kdf;
using Kdf108.Internal;

namespace Kdf108.Test.Sp800108;

/// <summary>
/// Zero-skip test vector loader that enforces strict loading of all test vectors.
/// This loader implements a strict policy: ALL test vectors MUST be loaded and executed.
/// </summary>
public static class KdfTestVectorLoader
{
    // Hard minimum test counts - strict validation enforced
    private static readonly Dictionary<string, int> MinimumTestCounts = new()
    {
        { "KDFCTR_gen.rsp", 4800 },
        { "KDFDblPipelineWithCtr_gen.rsp", 4800 },
        { "KDFDblPipelineWOCtr_gen.rsp", 400 },
        { "KDFFeedbackNoCtr_gen.rsp", 400 },
        { "KDFFeedbackNoZeroIV_gen.rsp", 4800 },
        { "KDFFeedbackWithZeroIV_gen.rsp", 4800 }
    };

    public static IEnumerable<KdfTestVector> LoadCounterModeVectors(string filePath)
    {
        var vectors = LoadVectorsWithValidation(filePath, TestVectorMode.Counter).ToList();
        ValidateMinimumTestCount(filePath, vectors.Count);
        return vectors;
    }

    public static IEnumerable<KdfTestVector> LoadFeedbackVectors(string filePath)
    {
        var vectors = LoadVectorsWithValidation(filePath, TestVectorMode.Feedback).ToList();
        ValidateMinimumTestCount(filePath, vectors.Count);
        return vectors;
    }

    public static IEnumerable<KdfTestVector> LoadDoublePipelineVectors(string filePath)
    {
        var vectors = LoadVectorsWithValidation(filePath, TestVectorMode.DoublePipeline).ToList();
        ValidateMinimumTestCount(filePath, vectors.Count);
        return vectors;
    }

    private static void ValidateMinimumTestCount(string filePath, int actualCount)
    {
        var fileName = Path.GetFileName(filePath);
        if (MinimumTestCounts.TryGetValue(fileName, out int expectedMinimum))
        {
            if (actualCount < expectedMinimum)
            {
                throw new InvalidOperationException(
                    $"Test validation failed: Expected at least {expectedMinimum} test vectors in {fileName}, " +
                    $"but only loaded {actualCount}. Zero-skip policy violation!");
            }
        }
        else
        {
            throw new InvalidOperationException(
                $"Test validation failed: Unknown test vector file {fileName}. " +
                $"All test files must be explicitly validated!");
        }
    }

    private static IEnumerable<KdfTestVector> LoadVectorsWithValidation(string filePath, TestVectorMode mode)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException(
                $"Test validation failed: Test vector file not found: {filePath}. " +
                $"All test vectors are mandatory!");
        }

        var lines = File.ReadAllLines(filePath)
            .Select(line => line.Trim())
            .Where(line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith('#'))
            .ToList();

        if (lines.Count == 0)
        {
            throw new InvalidOperationException(
                $"Test validation failed: No valid lines found in {filePath}. " +
                $"Test vector file appears to be empty or invalid!");
        }

        bool hasCounter = !filePath.Contains("NoCtr") && !filePath.Contains("nocounter");
        
        var vectors = ParseVectorsStrict(lines, mode, hasCounter, filePath).ToList();
        
        if (vectors.Count == 0)
        {
            throw new InvalidOperationException(
                $"Test validation failed: No test vectors parsed from {filePath}. " +
                $"This violates the zero-skip policy!");
        }

        return vectors;
    }

    private static IEnumerable<KdfTestVector> ParseVectorsStrict(
        List<string> lines, 
        TestVectorMode mode, 
        bool hasCounter, 
        string filePath)
    {
        var results = new List<KdfTestVector>();
        PrfType? currentPrf = null;
        CounterLocation? currentCtrlocation = null;
        int? currentRlen = null;
        Dictionary<string, string> currentVector = new();
        int? currentCount = null;
        int lineNumber = 0;

        void AddCurrentVector()
        {
            if (IsCompleteVector(currentVector) && currentCount.HasValue && currentPrf.HasValue)
            {
                var vector = CreateVectorStrict(currentCount.Value, currentVector, currentPrf.Value, 
                    currentCtrlocation ?? CounterLocation.BeforeFixed, currentRlen ?? 32, mode, filePath);
                results.Add(vector);
                currentVector = new Dictionary<string, string>();
                currentCount = null;
            }
        }

        foreach (string line in lines)
        {
            lineNumber++;
            
            try
            {
                if (line.StartsWith("[PRF="))
                {
                    AddCurrentVector();
                    string prfName = line.Substring(5, line.Length - 6);
                    currentPrf = ParsePrfTypeStrict(prfName, filePath, lineNumber);
                }
                else if (hasCounter && line.StartsWith("[CTRLOCATION="))
                {
                    AddCurrentVector();
                    string locationName = line.Substring(13, line.Length - 14);
                    currentCtrlocation = ParseCounterLocationStrict(locationName, mode, filePath, lineNumber);
                }
                else if (hasCounter && line.StartsWith("[RLEN="))
                {
                    AddCurrentVector();
                    string rlenStr = line.Substring(6, line.Length - 7);
                    currentRlen = ParseRlenStrict(rlenStr, filePath, lineNumber);
                }
                else if (line.StartsWith("COUNT"))
                {
                    AddCurrentVector();

                    if (currentPrf == null)
                    {
                        throw new InvalidOperationException(
                            $"Test parsing failed: COUNT found before PRF definition in {filePath} at line {lineNumber}");
                    }

                    string[] parts = line.Split('=');
                    if (parts.Length != 2)
                    {
                        throw new InvalidOperationException(
                            $"Test parsing failed: Invalid COUNT format in {filePath} at line {lineNumber}: {line}");
                    }
                    
                    if (!int.TryParse(parts[1].Trim(), out int count))
                    {
                        throw new InvalidOperationException(
                            $"Test parsing failed: Invalid COUNT value in {filePath} at line {lineNumber}: {parts[1]}");
                    }
                    
                    currentCount = count;
                }
                else if (line.Contains('='))
                {
                    if (currentPrf == null)
                    {
                        throw new InvalidOperationException(
                            $"Test parsing failed: Data line found before PRF definition in {filePath} at line {lineNumber}");
                    }

                    string[] lineParts = line.Split(new[] { '=' }, 2);
                    if (lineParts.Length != 2)
                    {
                        throw new InvalidOperationException(
                            $"Test parsing failed: Invalid data line format in {filePath} at line {lineNumber}: {line}");
                    }
                    
                    currentVector[lineParts[0].Trim()] = lineParts[1].Trim();
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Test parsing failed: Error parsing line {lineNumber} in {filePath}: {line}. " +
                    $"Original error: {ex.Message}", ex);
            }
        }

        // Process the final vector
        AddCurrentVector();

        if (results.Count == 0)
        {
            throw new InvalidOperationException(
                $"Test validation failed: No vectors produced from {filePath}. This violates zero-skip policy!");
        }

        return results;
    }

    private static KdfTestVector CreateVectorStrict(
        int count,
        Dictionary<string, string> data,
        PrfType prfType,
        CounterLocation counterLocation,
        int rlen,
        TestVectorMode mode,
        string filePath)
    {
        try
        {
            // Validate all required fields are present
            if (!data.ContainsKey("KI"))
                throw new InvalidOperationException($"Missing required field: KI");
            if (!data.ContainsKey("KO"))
                throw new InvalidOperationException($"Missing required field: KO");

            byte[] ki = ConvertCompat.FromHexString(data["KI"]);
            byte[] ko = ConvertCompat.FromHexString(data["KO"]);
            int lBits = data.TryGetValue("L", out string? lValue) ? int.Parse(lValue) : 128;

            // Get optional IV for feedback mode
            byte[]? iv = null;
            if (mode == TestVectorMode.Feedback && data.TryGetValue("IV", out string? ivValue) &&
                !string.IsNullOrEmpty(ivValue))
            {
                iv = ConvertCompat.FromHexString(ivValue);
            }

            // Handle middle counter location
            if (counterLocation == CounterLocation.MiddleFixed)
            {
                // Check if we have split data (DataBeforeCtrData/DataAfterCtrData)
                if (data.ContainsKey("DataBeforeCtrData") || data.ContainsKey("DataBeforeCtrLen") || 
                    data.ContainsKey("DataAfterCtrData") || data.ContainsKey("DataAfterCtrLen"))
                {
                    // Check for DataBeforeCtrData first, then fall back to DataBeforeCtrLen
                    if (!data.ContainsKey("DataBeforeCtrData") && data.ContainsKey("DataBeforeCtrLen"))
                    {
                        int beforeLen = int.Parse(data["DataBeforeCtrLen"]);
                        data["DataBeforeCtrData"] = new string('0', beforeLen * 2); // Pad with zeros
                    }
                    
                    // Check for DataAfterCtrData, then fall back to DataAfterCtrLen
                    if (!data.ContainsKey("DataAfterCtrData") && data.ContainsKey("DataAfterCtrLen"))
                    {
                        int afterLen = int.Parse(data["DataAfterCtrLen"]);
                        data["DataAfterCtrData"] = new string('0', afterLen * 2); // Pad with zeros
                    }
                    
                    if (!data.ContainsKey("DataBeforeCtrData"))
                        throw new InvalidOperationException($"Missing DataBeforeCtrData for middle counter location");
                    if (!data.ContainsKey("DataAfterCtrData"))
                        throw new InvalidOperationException($"Missing DataAfterCtrData for middle counter location");

                    byte[] dataBeforeCounter = ConvertCompat.FromHexString(data["DataBeforeCtrData"]);
                    byte[] dataAfterCounter = ConvertCompat.FromHexString(data["DataAfterCtrData"]);

                    return new KdfTestVector(
                        count, ki, prfType, counterLocation, rlen,
                        dataBeforeCounter: dataBeforeCounter,
                        dataAfterCounter: dataAfterCounter,
                        iv: iv,
                        lBits: lBits, ko: ko);
                }
                
                // Fall back to FixedInputData for middle counter location
                if (!data.ContainsKey("FixedInputData"))
                    throw new InvalidOperationException($"Missing FixedInputData for middle counter location");

                byte[] middleFixedInput = ConvertCompat.FromHexString(data["FixedInputData"]);

                return new KdfTestVector(
                    count, ki, prfType, counterLocation, rlen,
                    middleFixedInput, iv: iv, lBits: lBits, ko: ko);
            }

            // Handle standard fixed input data
            if (!data.ContainsKey("FixedInputData"))
                throw new InvalidOperationException($"Missing FixedInputData for standard counter location");

            byte[] fixedInput = ConvertCompat.FromHexString(data["FixedInputData"]);

            return new KdfTestVector(
                count, ki, prfType, counterLocation, rlen,
                fixedInput, iv: iv, lBits: lBits, ko: ko);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Test validation failed: Error creating test vector {count} in {filePath}. " +
                $"Original error: {ex.Message}", ex);
        }
    }

    private static bool IsCompleteVector(Dictionary<string, string> data)
    {
        if (!data.ContainsKey("KI") || !data.ContainsKey("KO"))
            return false;

        // For middle counter location
        if (data.ContainsKey("DataBeforeCtrLen") || data.ContainsKey("DataAfterCtrLen"))
            return data.ContainsKey("DataBeforeCtrData") && data.ContainsKey("DataAfterCtrData");

        // For standard cases
        return data.ContainsKey("FixedInputData");
    }

    private static PrfType? ParsePrfTypeStrict(string prfName, string filePath, int lineNumber)
    {
        return prfName switch
        {
            "CMAC_AES128" => PrfType.CmacAes128,
            "CMAC_AES192" => PrfType.CmacAes192,
            "CMAC_AES256" => PrfType.CmacAes256,
            "CMAC_TDES3" => PrfType.CmacTdes3,
            "CMAC_TDES2" => PrfType.CmacTdes2,
            "HMAC_SHA1" => PrfType.HmacSha1,
            "HMAC_SHA224" => PrfType.HmacSha224,
            "HMAC_SHA256" => PrfType.HmacSha256,
            "HMAC_SHA384" => PrfType.HmacSha384,
            "HMAC_SHA512" => PrfType.HmacSha512,
            _ => throw new NotSupportedException(
                $"Unsupported PRF type '{prfName}' in {filePath} at line {lineNumber}")
        };
    }

    private static CounterLocation ParseCounterLocationStrict(string location, TestVectorMode mode, string filePath, int lineNumber)
    {
        return (location, mode) switch
        {
            ("BEFORE_FIXED", _) => CounterLocation.BeforeFixed,
            ("AFTER_FIXED", _) => CounterLocation.AfterFixed,
            ("MIDDLE_FIXED", _) => CounterLocation.MiddleFixed,
            ("BEFORE_ITER", TestVectorMode.Feedback) => CounterLocation.BeforeFixed,
            ("AFTER_ITER", TestVectorMode.Feedback) => CounterLocation.MiddleFixed,
            ("BEFORE_ITER", TestVectorMode.DoublePipeline) => CounterLocation.BeforeFixed,
            ("AFTER_ITER", TestVectorMode.DoublePipeline) => CounterLocation.MiddleFixed,
            _ => throw new NotSupportedException(
                $"Test validation failed: Unsupported counter location '{location}' for mode {mode} " +
                $"in {filePath} at line {lineNumber}. All counter locations must be supported!")
        };
    }

    private static int ParseRlenStrict(string rlen, string filePath, int lineNumber)
    {
        return rlen switch
        {
            "8_BITS" => 8,
            "16_BITS" => 16,
            "24_BITS" => 24,
            "32_BITS" => 32,
            _ => throw new NotSupportedException(
                $"Test validation failed: Unsupported counter length '{rlen}' " +
                $"in {filePath} at line {lineNumber}. All counter lengths must be supported!")
        };
    }

    public sealed class KdfTestVector
    {
        public KdfTestVector(
            int count,
            byte[] ki,
            PrfType prfType,
            CounterLocation counterLocation,
            int rlenBits,
            byte[]? fixedInput = null,
            byte[]? dataBeforeCounter = null,
            byte[]? dataAfterCounter = null,
            byte[]? iv = null,
            int lBits = 128,
            byte[] ko = null!)
        {
            Count = count;
            Ki = ki;
            PrfType = prfType;
            CounterLocation = counterLocation;
            RlenBits = rlenBits;
            FixedInput = fixedInput;
            DataBeforeCounter = dataBeforeCounter;
            DataAfterCounter = dataAfterCounter;
            Iv = iv;
            LBits = lBits;
            Ko = ko!;
        }

        public int Count { get; }
        public byte[] Ki { get; }
        public PrfType PrfType { get; }
        public CounterLocation CounterLocation { get; }
        public int RlenBits { get; }
        public byte[]? FixedInput { get; }
        public byte[]? DataBeforeCounter { get; }
        public byte[]? DataAfterCounter { get; }
        public byte[]? Iv { get; }
        public int LBits { get; }
        public byte[] Ko { get; }
    }

    private enum TestVectorMode
    {
        Counter,
        Feedback,
        DoublePipeline
    }
}