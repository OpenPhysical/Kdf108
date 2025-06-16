// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Kdf108.Domain.Kdf;
using Kdf108.Internal;

#endregion


namespace Kdf108.Test.Kdf
{
    /// <summary>
    ///     A utility class for loading Key Derivation Function (KDF) test vectors.
    ///     Provides methods for reading and parsing test vector files.
    /// </summary>
    public static class KdfTestVectorLoader
    {
        /// <summary>
        ///     Loads KDF test vectors from a specified file.
        /// </summary>
        /// <param name="filePath">The path to the file containing the KDF test vectors.</param>
        /// <returns>A collection of KdfTestVector populated with test vector data from the file.</returns>
        public static IEnumerable<KdfTestVector> LoadCounterModeVectors(string filePath) =>
            LoadVectors(filePath, TestVectorMode.Counter);

        /// <summary>
        ///     Loads KDF Feedback Mode test vectors from a specified file.
        /// </summary>
        /// <param name="filePath">The path to the file containing the KDF Feedback Mode test vectors.</param>
        /// <returns>A collection of KdfTestVector populated with test vector data from the file.</returns>
        public static IEnumerable<KdfTestVector> LoadFeedbackVectors(string filePath) =>
            LoadVectors(filePath, TestVectorMode.Feedback);

        /// <summary>
        ///     Loads KDF Double-Pipeline Mode test vectors from a specified file.
        /// </summary>
        /// <param name="filePath">The path to the file containing the KDF Double-Pipeline Mode test vectors.</param>
        /// <returns>A collection of KdfTestVector populated with test vector data from the file.</returns>
        public static IEnumerable<KdfTestVector> LoadDoublePipelineVectors(string filePath) =>
            LoadVectors(filePath, TestVectorMode.DoublePipeline);

        private static IEnumerable<KdfTestVector> LoadVectors(string filePath, TestVectorMode mode)
        {
            // Parse the raw file into lines and filter out comments and empty lines
            List<string> lines = File.ReadAllLines(filePath)
                .Select(static line => line.Trim())
                .Where(static line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                .ToList();

            bool hasCounter = !filePath.Contains("NoCtr") && !filePath.Contains("nocounter");

            // Process vectors using a functional approach
            return ParseVectorsFromLines(lines, mode, hasCounter);
        }

        /// <summary>
        /// Parses a list of test vector lines and produces a collection of KDF test vectors.
        /// </summary>
        /// <param name="lines">The list of lines representing test vectors, excluding comments and empty lines.</param>
        /// <param name="mode">The mode of the test vectors, specifying the type of KDF operation.</param>
        /// <param name="hasCounter">A flag indicating whether the test vector includes a counter.</param>
        /// <returns>A collection of KdfTestVector representing the parsed test vectors.</returns>
        private static IEnumerable<KdfTestVector> ParseVectorsFromLines(List<string> lines, TestVectorMode mode,
            bool hasCounter)
        {
            // State tracking
            PrfType? currentPrf = null;
            CounterLocation? currentCtrlocation = null;
            int? currentRlen = null;
            Dictionary<string, string> currentVector = new();
            int? currentCount = null;

            // Process lines one at a time
            foreach (string? line in lines)
            {
                if (TryProcessSectionHeader(
                        line,
                        ref currentPrf,
                        ref currentCtrlocation,
                        ref currentRlen,
                        ref currentVector,
                        ref currentCount,
                        hasCounter,
                        mode,
                        out KdfTestVector? vector))
                {
                    if (vector != null)
                    {
                        yield return vector;
                    }

                    continue;
                }

                if (currentPrf == null) // Skip processing if we're in a section to be skipped
                {
                    continue;
                }

                if (TryProcessVectorLine(
                        line,
                        ref currentVector,
                        ref currentCount,
                        hasCounter,
                        currentPrf.Value,
                        currentCtrlocation,
                        currentRlen,
                        mode,
                        out vector))
                {
                    if (vector != null)
                    {
                        yield return vector;
                    }
                }
            }

            // Process the last vector if complete
            if (IsCompleteVector(currentVector) && currentCount.HasValue && currentPrf.HasValue &&
                (!hasCounter || (currentCtrlocation.HasValue && currentRlen.HasValue)))
            {
                yield return CreateVector(
                    currentCount.Value,
                    currentVector,
                    currentPrf.Value,
                    currentCtrlocation ?? CounterLocation.BeforeFixed,
                    currentRlen ?? 32,
                    mode);
            }
        }

        private static bool TryProcessSectionHeader(
            string line,
            ref PrfType? currentPrf,
            ref CounterLocation? currentCtrlocation,
            ref int? currentRlen,
            ref Dictionary<string, string> currentVector,
            ref int? currentCount,
            bool hasCounter,
            TestVectorMode mode,
            out KdfTestVector? vector)
        {
            vector = null;

            if (line.StartsWith("[PRF="))
            {
                // Process any pending vector when we hit a new section
                if (IsCompleteVector(currentVector) && currentCount.HasValue && currentPrf.HasValue &&
                    (!hasCounter || (currentCtrlocation.HasValue && currentRlen.HasValue)))
                {
                    vector = CreateVector(
                        currentCount.Value,
                        currentVector,
                        currentPrf.Value,
                        currentCtrlocation ?? CounterLocation.BeforeFixed,
                        currentRlen ?? 32,
                        mode);

                    currentVector = new Dictionary<string, string>();
                    currentCount = null;
                }

                string prfName = line.Substring(5, line.Length - 6);
                currentPrf = TryParsePrfType(prfName);

                // If currentPrf is null, we're skipping this section (e.g., unsupported PRF)
                if (currentPrf != null)
                {
                    return true;
                }

                Console.WriteLine($"Skipping unsupported PRF type: {prfName}");
                currentVector.Clear();
                currentCount = null;

                return true;
            }

            if (hasCounter && line.StartsWith("[CTRLOCATION="))
            {
                // Process any pending vector when we hit a new section
                if (IsCompleteVector(currentVector) && currentCount.HasValue && currentPrf.HasValue &&
                    currentCtrlocation.HasValue && currentRlen.HasValue)
                {
                    vector = CreateVector(
                        currentCount.Value,
                        currentVector,
                        currentPrf.Value,
                        currentCtrlocation.Value,
                        currentRlen.Value,
                        mode);

                    currentVector = new Dictionary<string, string>();
                    currentCount = null;
                }

                string locationName = line.Substring(13, line.Length - 14);
                currentCtrlocation = ParseCounterLocation(locationName, mode);
                return true;
            }

            if (!hasCounter || !line.StartsWith("[RLEN="))
            {
                return false;
            }

            // Process any pending vector when we hit a new section
            if (IsCompleteVector(currentVector) && currentCount.HasValue && currentPrf.HasValue &&
                currentCtrlocation.HasValue && currentRlen.HasValue)
            {
                vector = CreateVector(
                    currentCount.Value,
                    currentVector,
                    currentPrf.Value,
                    currentCtrlocation.Value,
                    currentRlen.Value,
                    mode);

                currentVector = new Dictionary<string, string>();
                currentCount = null;
            }

            string rlenStr = line.Substring(6, line.Length - 7);
            currentRlen = ParseRlen(rlenStr);
            return true;
        }

        private static bool TryProcessVectorLine(
            string line,
            ref Dictionary<string, string> currentVector,
            ref int? currentCount,
            bool hasCounter,
            PrfType currentPrf,
            CounterLocation? currentCtrlocation,
            int? currentRlen,
            TestVectorMode mode,
            out KdfTestVector? vector)
        {
            vector = null;

            if (line.StartsWith("COUNT"))
            {
                // Process any pending vector when we hit a new COUNT
                if (IsCompleteVector(currentVector) && currentCount.HasValue &&
                    (!hasCounter || (currentCtrlocation.HasValue && currentRlen.HasValue)))
                {
                    vector = CreateVector(
                        currentCount.Value,
                        currentVector,
                        currentPrf,
                        currentCtrlocation ?? CounterLocation.BeforeFixed,
                        currentRlen ?? 32,
                        mode);

                    currentVector = new Dictionary<string, string>();
                }

                string[] parts = line.Split('=');
                currentCount = int.Parse(parts[1].Trim());
                return true;
            }

            if (!line.Contains('='))
            {
                return false;
            }

            string[] lineParts = line.Split(new[] { '=' }, 2);
            currentVector[lineParts[0].Trim()] = lineParts[1].Trim();
            return true;
        }

        /// <summary>
        ///     Creates a KdfTestVector from the parsed data.
        /// </summary>
        private static KdfTestVector CreateVector(
            int count,
            Dictionary<string, string> data,
            PrfType prfType,
            CounterLocation counterLocation,
            int rlen,
            TestVectorMode mode)
        {
            // Get required parameters
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

            // Handle middle counter location if needed
            if (counterLocation == CounterLocation.MiddleFixed &&
                data.ContainsKey("DataBeforeCtrData") &&
                data.TryGetValue("DataAfterCtrData", out string? afterValue))
            {
                byte[] dataBeforeCounter = ConvertCompat.FromHexString(data["DataBeforeCtrData"]);
                byte[] dataAfterCounter = ConvertCompat.FromHexString(afterValue);

                return new KdfTestVector(
                    count, ki, prfType, counterLocation, rlen,
                    dataBeforeCounter: dataBeforeCounter,
                    dataAfterCounter: dataAfterCounter,
                    iv: iv,
                    lBits: lBits, ko: ko);
            }

            // Handle standard fixed input data
            byte[] fixedInput = data.TryGetValue("FixedInputData", out string? fixedValue)
                ? ConvertCompat.FromHexString(fixedValue)
                : Array.Empty<byte>();

            return new KdfTestVector(
                count, ki, prfType, counterLocation, rlen,
                fixedInput, iv: iv, lBits: lBits, ko: ko);
        }

        /// <summary>
        ///     Determines if the provided vector data is complete and satisfies all necessary requirements.
        /// </summary>
        private static bool IsCompleteVector(Dictionary<string, string> data)
        {
            // Basic requirements for any vector
            if (!data.ContainsKey("KI") || !data.ContainsKey("KO"))
            {
                return false;
            }

            // For middle counter location
            if (data.ContainsKey("DataBeforeCtrLen") || data.ContainsKey("DataAfterCtrLen"))
                // Need both before and after data
            {
                return data.ContainsKey("DataBeforeCtrData") && data.ContainsKey("DataAfterCtrData");
            }

            // For standard cases, fixed input data is required
            return data.ContainsKey("FixedInputData");
        }

        /// <summary>
        ///     Safely attempts to parse a PRF type string, returning null for unsupported types.
        /// </summary>
        private static PrfType? TryParsePrfType(string prfName) =>
            prfName switch
            {
                "CMAC_AES128" => PrfType.CmacAes128,
                "CMAC_AES192" => PrfType.CmacAes192,
                "CMAC_AES256" => PrfType.CmacAes256,
                "CMAC_TDES3" => PrfType.CmacTdes3,
                "HMAC_SHA1" => PrfType.HmacSha1,
                "HMAC_SHA224" => PrfType.HmacSha224,
                "HMAC_SHA256" => PrfType.HmacSha256,
                "HMAC_SHA384" => PrfType.HmacSha384,
                "HMAC_SHA512" => PrfType.HmacSha512,
                "CMAC_TDES2" => null, // Skip unsupported TDES2
                _ => throw new ArgumentException($"Unsupported PRF type: {prfName}")
            };

        /// <summary>
        ///     Parses a counter location string into the corresponding CounterLocation enum value,
        ///     taking into account the KDF mode.
        /// </summary>
        private static CounterLocation ParseCounterLocation(string location, TestVectorMode mode) =>
            (location, mode) switch
            {
                ("BEFORE_FIXED", _) => CounterLocation.BeforeFixed,
                ("AFTER_FIXED", _) => CounterLocation.AfterFixed,
                ("MIDDLE_FIXED", _) => CounterLocation.MiddleFixed,

                // For feedback mode
                ("BEFORE_ITER", TestVectorMode.Feedback) => CounterLocation.BeforeFixed,
                ("AFTER_ITER", TestVectorMode.Feedback) => CounterLocation.MiddleFixed,

                // For double-pipeline mode
                ("BEFORE_ITER", TestVectorMode.DoublePipeline) => CounterLocation.BeforeFixed,
                ("AFTER_ITER", TestVectorMode.DoublePipeline) => CounterLocation.MiddleFixed,

                _ => throw new ArgumentException($"Unsupported counter location: {location} for mode {mode}")
            };

        /// <summary>
        ///     Parses a counter length string into the corresponding integer bit length.
        /// </summary>
        private static int ParseRlen(string rlen) =>
            rlen switch
            {
                "8_BITS" => 8,
                "16_BITS" => 16,
                "24_BITS" => 24,
                "32_BITS" => 32,
                _ => throw new ArgumentException($"Unsupported counter length: {rlen}")
            };

        /// <summary>
        ///     Represents a test vector for key derivation function (KDF) testing.
        /// </summary>
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
}
