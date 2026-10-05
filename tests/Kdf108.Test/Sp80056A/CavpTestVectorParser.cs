using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Kdf108.Test.Sp80056A;

/// <summary>
/// Parses CAVP test vectors for SP 800-56A Key Agreement schemes.
/// </summary>
public static class CavpTestVectorParser
{
    /// <summary>
    /// Parses a CAVP test vector file.
    /// </summary>
    /// <param name="filePath">Path to the test vector file.</param>
    /// <returns>Collection of parsed test vectors.</returns>
    public static IEnumerable<CavpTestVector> ParseFile(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("Required CAVP vector file was not found.", filePath);

        var lines = File.ReadAllLines(filePath);
        var vectors = new List<CavpTestVector>();
        
        string? currentParameterSet = null;
        string? currentCurve = null;
        string? currentHash = null;
        string? currentMacAlgorithm = null;
        string? currentMacVariant = null;
        var metadata = CavpSourceMetadata.FromPath(filePath);
        var currentVector = new CavpTestVector { Source = metadata };
        var sectionFields = new Dictionary<string, string>(StringComparer.Ordinal);
        
        // Track parameter set to curve mapping for this file
        var parameterSetToCurve = new Dictionary<string, string>();
        
        foreach (var line in lines)
        {
            var trimmedLine = line.Trim();
            
            // Skip empty lines and comments
            if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith('#'))
                continue;
            
            // Parse parameter set
            if (trimmedLine.StartsWith('[') && trimmedLine.EndsWith(']'))
            {
                var section = trimmedLine[1..^1];
                
                if (section.StartsWith("Curve selected:"))
                {
                    currentCurve = section["Curve selected:".Length..].Trim();
                    // If we have a current parameter set, update the mapping
                    if (currentParameterSet != null)
                    {
                        parameterSetToCurve[currentParameterSet] = currentCurve;
                    }
                }
                else if (section.Contains("SHA") && section.Contains("supported"))
                {
                    // This is a SHA specification line, extract the hash
                    currentHash = ExtractHashFromSection(section);
                }
                else if (section.Length <= 2) // Parameter sets like EB, EC, etc.
                {
                    currentParameterSet = section;
                    // When we see a new parameter set, look up its curve
                    if (parameterSetToCurve.TryGetValue(currentParameterSet, out var mappedCurve))
                    {
                        currentCurve = mappedCurve;
                    }
                }
                else if (section.Contains(" - "))
                {
                    // Section like "EB - SHA512"
                    var parts = section.Split(" - ");
                    if (parts.Length == 2)
                    {
                        currentParameterSet = parts[0];
                        currentHash = parts[1];
                        
                        // Use the recorded curve for this parameter set
                        if (parameterSetToCurve.TryGetValue(currentParameterSet, out var mappedCurve))
                        {
                            currentCurve = mappedCurve;
                        }
                    }
                }
                else if (section.StartsWith("MAC algorithm supported:", StringComparison.Ordinal))
                {
                    currentMacAlgorithm = section.Split(':', 2)[1].Trim();
                }
                else if (section.StartsWith("CCM AES", StringComparison.Ordinal) ||
                         section.StartsWith("CMAC AES", StringComparison.Ordinal) ||
                         section.StartsWith("HMAC SHA", StringComparison.Ordinal))
                {
                    currentMacVariant = section;
                    currentMacAlgorithm = section.Split(' ', 2)[0];
                }
                continue;
            }
            
            // Parse test vector data
            if (trimmedLine.Contains(" = "))
            {
                var parts = trimmedLine.Split(" = ", 2);
                if (parts.Length == 2)
                {
                    var key = parts[0].Trim();
                    var value = parts[1].Trim();
                    
                    switch (key)
                    {
                        case "COUNT":
                            // Save previous vector if exists
                            if (currentVector.Count.HasValue)
                            {
                                vectors.Add(currentVector);
                            }
                            
                            // Start new vector
                            currentVector = new CavpTestVector
                            {
                                Count = int.Parse(value),
                                ParameterSet = currentParameterSet,
                                Curve = currentCurve,
                                Hash = currentHash,
                                Source = metadata,
                                MacAlgorithm = currentMacAlgorithm,
                                MacVariant = currentMacVariant
                            };
                            foreach (var pair in sectionFields)
                                currentVector.Fields.Add(pair.Key, pair.Value);
                            break;
                            
                        case "deCAVS":
                            currentVector.DeCAVS = ParseHexString(value);
                            break;
                            
                        case "QeCAVSx":
                            currentVector.QeCAVSx = ParseHexString(value);
                            break;
                            
                        case "QeCAVSy":
                            currentVector.QeCAVSy = ParseHexString(value);
                            break;
                            
                        case "deIUT":
                            currentVector.DeIUT = ParseHexString(value);
                            break;
                            
                        case "QeIUTx":
                            currentVector.QeIUTx = ParseHexString(value);
                            break;
                            
                        case "QeIUTy":
                            currentVector.QeIUTy = ParseHexString(value);
                            break;
                            
                        case "dsCAVS":
                            currentVector.DsCAVS = ParseHexString(value);
                            break;
                            
                        case "QsCAVSx":
                            currentVector.QsCAVSx = ParseHexString(value);
                            break;
                            
                        case "QsCAVSy":
                            currentVector.QsCAVSy = ParseHexString(value);
                            break;
                            
                        case "dsIUT":
                            currentVector.DsIUT = ParseHexString(value);
                            break;
                            
                        case "QsIUTx":
                            currentVector.QsIUTx = ParseHexString(value);
                            break;
                            
                        case "QsIUTy":
                            currentVector.QsIUTy = ParseHexString(value);
                            break;
                            
                        case "Z":
                            currentVector.Z = ParseHexString(value);
                            break;
                            
                        case "CAVSHashZZ":
                            currentVector.CAVSHashZZ = ParseHexString(value);
                            break;
                            
                        case "Nonce":
                            currentVector.Nonce = ParseHexString(value);
                            break;
                            
                        case "OI":
                            currentVector.OI = ParseHexString(value);
                            break;
                            
                        case "CAVSTag":
                            currentVector.CAVSTag = ParseHexString(value);
                            break;
                            
                        case "MacData":
                            currentVector.MacData = ParseHexString(value);
                            break;
                            
                        case "DKM":
                            currentVector.DKM = ParseHexString(value);
                            break;
                            
                        case "Result":
                            currentVector.Result = value;
                            break;
                    }

                    if (key is "P" or "Q" or "G")
                        sectionFields[key] = value;
                    else if (!currentVector.Fields.TryAdd(key, value))
                        throw new InvalidDataException($"Duplicate field '{key}' in {filePath}, vector {currentVector.Count}.");
                }
            }
        }
        
        // Add the last vector
        if (currentVector.Count.HasValue)
        {
            vectors.Add(currentVector);
        }
        
        foreach (var vector in vectors)
            vector.ValidateMetadata();

        return vectors;
    }
    
    private static string? ExtractHashFromSection(string section)
    {
        // Extract hash from sections like "SHA(s) supported (Used for hashing Z):  SHA512"
        if (section.Contains("SHA"))
        {
            var hashPart = section.Split(':').LastOrDefault()?.Trim();
            if (!string.IsNullOrEmpty(hashPart))
            {
                // Take first hash if multiple are listed
                return hashPart.Split(' ').FirstOrDefault(h => h.StartsWith("SHA"));
            }
        }
        return null;
    }
    
    private static string? GetCurveFromParameterSet(string? parameterSet)
    {
        // Map parameter sets to curves based on CAVP test vector conventions
        // Note: The same parameter set can map to different curves in different files
        // This is just a fallback when the curve isn't explicitly set
        return parameterSet switch
        {
            "EA" => "P-192",
            "EB" => "P-224",  // or B-233 in binary curve files
            "EC" => "P-256",  // or K-283 in binary curve files
            "ED" => "P-384",  // or B-409 in binary curve files
            "EE" => "P-521",  // or B-571 in binary curve files
            _ => null
        };
    }
    
    private static byte[] ParseHexString(string hexString)
    {
        if (string.IsNullOrEmpty(hexString))
            return Array.Empty<byte>();
        
        // Remove any spaces or prefixes
        hexString = hexString.Replace(" ", "").Replace("0x", "");
        
        // Ensure even length
        if (hexString.Length % 2 != 0)
            hexString = "0" + hexString;
        
        var bytes = new byte[hexString.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = byte.Parse(hexString.Substring(i * 2, 2), NumberStyles.HexNumber);
        }
        
        return bytes;
    }
}

/// <summary>
/// Represents a single CAVP test vector for SP 800-56A.
/// </summary>
public class CavpTestVector
{
    public int? Count { get; set; }
    public string? ParameterSet { get; set; }
    public string? Curve { get; set; }
    public string? Hash { get; set; }
    public CavpSourceMetadata Source { get; set; } = CavpSourceMetadata.Unknown;
    public string? MacAlgorithm { get; set; }
    public string? MacVariant { get; set; }
    public Dictionary<string, string> Fields { get; } = new(StringComparer.Ordinal);
    
    // Ephemeral private keys
    public byte[]? DeCAVS { get; set; }
    public byte[]? DeIUT { get; set; }
    
    // Static private keys
    public byte[]? DsCAVS { get; set; }
    public byte[]? DsIUT { get; set; }
    
    // Ephemeral public key coordinates
    public byte[]? QeCAVSx { get; set; }
    public byte[]? QeCAVSy { get; set; }
    public byte[]? QeIUTx { get; set; }
    public byte[]? QeIUTy { get; set; }
    
    // Static public key coordinates
    public byte[]? QsCAVSx { get; set; }
    public byte[]? QsCAVSy { get; set; }
    public byte[]? QsIUTx { get; set; }
    public byte[]? QsIUTy { get; set; }
    
    // Shared secret and derived values
    public byte[]? Z { get; set; }
    public byte[]? CAVSHashZZ { get; set; }
    
    // KDF-specific fields
    public byte[]? Nonce { get; set; }
    public byte[]? OI { get; set; }
    public byte[]? CAVSTag { get; set; }
    public byte[]? MacData { get; set; }
    public byte[]? DKM { get; set; }
    
    // Test result
    public string? Result { get; set; }
    
    /// <summary>
    /// Indicates if this test vector expects a passing result.
    /// </summary>
    public bool ExpectPass => Result?.StartsWith("P") == true;
    
    /// <summary>
    /// Indicates if this test vector expects a failing result.
    /// </summary>
    public bool ExpectFail => Result?.StartsWith("F") == true;
    
    /// <summary>
    /// Gets the error code from the result field.
    /// </summary>
    public string? ErrorCode
    {
        get
        {
            if (string.IsNullOrEmpty(Result))
                return null;
            
            // Look for pattern: F (n - description)
            var match = System.Text.RegularExpressions.Regex.Match(Result, @"F\s*\((\d+)\s*-");
            if (match.Success)
            {
                return match.Groups[1].Value;
            }
            
            return null;
        }
    }

    public int ResultCode => int.Parse(
        Regex.Match(Result ?? string.Empty, @"^[PF]\s*\((\d+)\s*-").Groups[1].Value,
        CultureInfo.InvariantCulture);

    internal void ValidateMetadata()
    {
        if (!Count.HasValue)
            throw new InvalidDataException($"Vector in {Source.FilePath} has no COUNT.");
        if (string.IsNullOrWhiteSpace(ParameterSet))
            throw new InvalidDataException($"Vector {Count} in {Source.FilePath} has no parameter set.");
        if (Source.Family == CavpFamily.Ecc && string.IsNullOrWhiteSpace(Curve))
            throw new InvalidDataException($"ECC vector {Count} in {Source.FilePath} has no curve metadata.");
        if (string.IsNullOrWhiteSpace(Result) || !Regex.IsMatch(Result, @"^[PF]\s*\(\d+\s*-.*\)$"))
            throw new InvalidDataException($"Vector {Count} in {Source.FilePath} has malformed Result metadata: '{Result}'.");
        if (ExpectPass && ResultCode is not (0 or 10 or 11 or 13 or 14))
            throw new InvalidDataException($"Vector {Count} in {Source.FilePath} has unknown passing result code {ResultCode}.");
        if (ExpectFail && ResultCode is < 1 or > 12)
            throw new InvalidDataException($"Vector {Count} in {Source.FilePath} has unknown failing result code {ResultCode}.");
    }
    
    /// <summary>
    /// Gets the error description from the result field.
    /// </summary>
    public string? ErrorDescription
    {
        get
        {
            if (string.IsNullOrEmpty(Result))
                return null;
            
            var parenStart = Result.IndexOf('(');
            var parenEnd = Result.LastIndexOf(')');
            
            if (parenStart >= 0 && parenEnd > parenStart)
            {
                var errorInfo = Result.Substring(parenStart + 1, parenEnd - parenStart - 1);
                var dashIndex = errorInfo.IndexOf(" - ");
                if (dashIndex >= 0)
                {
                    return errorInfo.Substring(dashIndex + 3).Trim();
                }
            }
            
            return null;
        }
    }
    
    public override string ToString()
    {
        return $"Count={Count}, ParameterSet={ParameterSet}, Curve={Curve}, Hash={Hash}, Result={Result}";
    }
}

public enum CavpFamily { Ecc, Ffc, Unknown }
public enum CavpStage { Zz, KdfNoKeyConfirmation, KeyConfirmation, Unknown }

public sealed record CavpSourceMetadata(
    string FilePath,
    CavpFamily Family,
    CavpStage Stage,
    string Scheme,
    string Role)
{
    public static CavpSourceMetadata Unknown { get; } =
        new(string.Empty, CavpFamily.Unknown, CavpStage.Unknown, string.Empty, string.Empty);

    public static CavpSourceMetadata FromPath(string filePath)
    {
        string normalized = filePath.Replace('\\', '/');
        var family = normalized.Contains("KASTestVectorsECC2016", StringComparison.Ordinal)
            ? CavpFamily.Ecc
            : normalized.Contains("KASTestVectorsFFC2016", StringComparison.Ordinal)
                ? CavpFamily.Ffc
                : CavpFamily.Unknown;
        var stage = normalized.Contains("Test of 800-56A excluding KDF", StringComparison.Ordinal)
            ? CavpStage.Zz
            : normalized.Contains("No Key Confirmation", StringComparison.Ordinal)
                ? CavpStage.KdfNoKeyConfirmation
                : normalized.Contains("Key Confirmation", StringComparison.Ordinal)
                    ? CavpStage.KeyConfirmation
                    : CavpStage.Unknown;
        string scheme = Directory.GetParent(filePath)?.Name ?? string.Empty;
        string name = Path.GetFileNameWithoutExtension(filePath);
        string role = name.Contains("_init", StringComparison.Ordinal) ? "initiator" :
            name.Contains("_resp", StringComparison.Ordinal) ? "responder" : string.Empty;
        if (family == CavpFamily.Unknown || stage == CavpStage.Unknown || role.Length == 0)
            throw new InvalidDataException($"Cannot classify CAVP source path '{filePath}'.");
        return new CavpSourceMetadata(filePath, family, stage, scheme, role);
    }
}
