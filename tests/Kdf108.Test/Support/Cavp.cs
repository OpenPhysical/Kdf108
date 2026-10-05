using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Kdf108.Test.Support;

/// <summary>Shared plumbing for per-file CAVP tests.</summary>
internal static class Cavp
{
    /// <summary>The marker <c>verify-conformance-results.ps1</c> sums from TRX output to prove execution counts.</summary>
    internal const string EvidencePrefix = "cavp-vectors-executed:";

    private static readonly Lazy<JsonDocument> ManifestDocument = new(() =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(TestPaths.Project, "..", "conformance-manifest.json"))));

    internal static JsonElement Manifest => ManifestDocument.Value.RootElement;

    /// <summary>The manifest entry for a pinned SP 800-108 corpus file.</summary>
    internal static (int Conforming, int Legacy) ExpectedCorpusCounts(string fileName)
    {
        foreach (JsonElement corpus in Manifest.GetProperty("corpora").EnumerateArray())
        {
            if (Path.GetFileName(corpus.GetProperty("path").GetString()) == fileName)
                return (corpus.GetProperty("expectedConformingVectors").GetInt32(),
                        corpus.GetProperty("expectedLegacyDiagnosticVectors").GetInt32());
        }
        throw new InvalidDataException($"{fileName} is not listed in conformance-manifest.json.");
    }

    /// <summary>
    /// Runs every vector, collects every failure (not just the first), fails with the full list,
    /// and writes the executed count as evidence.
    /// </summary>
    internal static void RunAll<T>(IEnumerable<T> vectors, Action<T> check, Func<T, string> describe)
    {
        var failures = new List<string>();
        int executed = 0;
        foreach (T vector in vectors)
        {
            executed++;
            try { check(vector); }
            catch (Exception ex) { failures.Add($"{describe(vector)}: {ex.GetType().Name}: {FirstLine(ex.Message)}"); }
        }

        Assert.That(executed, Is.GreaterThan(0), "No vectors were executed.");
        Assert.That(failures, Is.Empty, $"{failures.Count} of {executed} vectors failed:{Environment.NewLine}" +
            string.Join(Environment.NewLine, failures.Take(50)));
        TestContext.Out.WriteLine($"{EvidencePrefix} {executed}");
    }

    private static string FirstLine(string message)
    {
        int newline = message.IndexOfAny(new[] { '\r', '\n' });
        return newline < 0 ? message : message[..newline];
    }
}
