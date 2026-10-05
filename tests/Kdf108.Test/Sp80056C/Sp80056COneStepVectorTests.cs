using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Kdf108.Test.Support;

namespace Kdf108.Test.Nist80056C;

/// <summary>
/// Unofficial SP 800-56C one-step vectors (NIST publishes none). Each vector runs through the
/// production one-step API; the exact count proves no line is silently skipped.
/// </summary>
[TestFixture]
public partial class Sp80056COneStepVectorTests
{
    private const int ExpectedVectorCount = 372;

    internal sealed record Vector(string Function, byte[] Z, int LengthBytes, byte[]? Salt, byte[] FixedInfo, byte[] Expected, int Line);

    [GeneratedRegex(@"^\(z:\s*([0-9a-fA-F]+),\s*L:\s*(\d+),(?:\s*salt:\s*([0-9a-fA-F]*),)?\s*fixedInfo:\s*([0-9a-fA-F]*)\)\s*=\s*([0-9a-fA-F]+)$")]
    private static partial Regex VectorLine();

    internal static IReadOnlyList<Vector> Load()
    {
        var vectors = new List<Vector>();
        string? function = null;
        int lineNumber = 0;
        foreach (string raw in File.ReadLines(TestPaths.Vectors("SP800-56C", "test_vectors.txt")))
        {
            lineNumber++;
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            if (line.StartsWith('[') && line.EndsWith(']')) { function = line[1..^1]; continue; }

            var match = VectorLine().Match(line);
            if (!match.Success || function is null)
                throw new InvalidDataException($"Unparseable SP 800-56C vector at line {lineNumber}: {line}");
            vectors.Add(new Vector(
                function,
                Convert.FromHexString(match.Groups[1].Value),
                int.Parse(match.Groups[2].Value),
                match.Groups[3].Success ? Convert.FromHexString(match.Groups[3].Value) : null,
                Convert.FromHexString(match.Groups[4].Value),
                Convert.FromHexString(match.Groups[5].Value),
                lineNumber));
        }
        return vectors;
    }

    [Test]
    public void EveryVectorIsParsed() => Assert.That(Load(), Has.Count.EqualTo(ExpectedVectorCount));

    [Test]
    public void EveryVectorMatchesTheProductionOneStepKdf()
    {
        var failures = Load().Where(v => !Derive(v).AsSpan().SequenceEqual(v.Expected))
            .Select(v => $"line {v.Line} ({v.Function})").ToList();
        Assert.That(failures, Is.Empty);
    }

    private static byte[] Derive(Vector v)
    {
        var function = v.Function switch
        {
            "SHA-1" => OneStepFunction.HashFunction(NistHashAlgorithm.Sha1),
            "SHA-256" => OneStepFunction.HashFunction(NistHashAlgorithm.Sha256),
            "SHA-512" => OneStepFunction.HashFunction(NistHashAlgorithm.Sha512),
            "HMAC-SHA256" => OneStepFunction.Hmac(NistHashAlgorithm.Sha256, v.Salt),
            "HMAC-SHA512" => OneStepFunction.Hmac(NistHashAlgorithm.Sha512, v.Salt),
            _ => throw new InvalidDataException($"Unknown function '{v.Function}'.")
        };
        return Sp80056C.OneStep(v.Z, function, v.FixedInfo, BitLength.FromBytes(v.LengthBytes), SecurityStrength.Bits112);
    }
}
