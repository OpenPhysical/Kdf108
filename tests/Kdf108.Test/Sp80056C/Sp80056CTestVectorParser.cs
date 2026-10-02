using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace Kdf108.Test.Sp80056C;

/// <summary>
/// Parser for SP 800-56C test vectors.
/// </summary>
public static class Sp80056CTestVectorParser
{
    public class TestVector
    {
        public string HashAlgorithm { get; set; } = "";
        public byte[] Z { get; set; } = Array.Empty<byte>();
        public int L { get; set; }
        public byte[] FixedInfo { get; set; } = Array.Empty<byte>();
        public byte[] Expected { get; set; } = Array.Empty<byte>();
    }

    public static List<TestVector> ParseFile(string filePath)
    {
        var vectors = new List<TestVector>();
        var lines = File.ReadAllLines(filePath);
        string? currentHashAlgorithm = null;

        foreach (var line in lines)
        {
            var trimmedLine = line.Trim();
            
            // Skip empty lines and comments
            if (string.IsNullOrWhiteSpace(trimmedLine) || trimmedLine.StartsWith("#"))
                continue;

            // Check for hash algorithm section
            var hashMatch = Regex.Match(trimmedLine, @"^\[([^\]]+)\]$");
            if (hashMatch.Success)
            {
                currentHashAlgorithm = hashMatch.Groups[1].Value;
                continue;
            }

            // Parse test vector line
            // Format: (z: <hex>, L: <decimal>, fixedInfo: <hex>) = <hex>
            var vectorMatch = Regex.Match(trimmedLine, 
                @"\(z:\s*([0-9a-fA-F]+),\s*L:\s*(\d+),\s*fixedInfo:\s*([0-9a-fA-F]*)\)\s*=\s*([0-9a-fA-F]+)");
            
            if (vectorMatch.Success && currentHashAlgorithm != null)
            {
                var vector = new TestVector
                {
                    HashAlgorithm = currentHashAlgorithm,
                    Z = HexToBytes(vectorMatch.Groups[1].Value),
                    L = int.Parse(vectorMatch.Groups[2].Value),
                    FixedInfo = HexToBytes(vectorMatch.Groups[3].Value),
                    Expected = HexToBytes(vectorMatch.Groups[4].Value)
                };
                
                vectors.Add(vector);
            }
        }

        return vectors;
    }

    private static byte[] HexToBytes(string hex)
    {
        if (string.IsNullOrEmpty(hex))
            return Array.Empty<byte>();

        if (hex.Length % 2 != 0)
            hex = "0" + hex;

        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }
}