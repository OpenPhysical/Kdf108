using System;
using System.Collections.Generic;
using System.IO;

namespace Kdf108.Test.Support;

/// <summary>One CAVP response record: the section headers in force and the record's fields.</summary>
internal sealed record RspRecord(
    string File,
    int Line,
    IReadOnlyList<string> AllHeaders,
    int HeaderCount,
    IReadOnlyDictionary<string, string> Fields)
{
    /// <summary>Every header seen in the file up to this record, oldest first.</summary>
    internal IEnumerable<string> Headers
    {
        get { for (int i = 0; i < HeaderCount; i++) yield return AllHeaders[i]; }
    }

    /// <summary>The most recent header satisfying <paramref name="predicate"/>, or null.</summary>
    internal string? LatestHeader(Func<string, bool> predicate)
    {
        for (int i = HeaderCount - 1; i >= 0; i--)
            if (predicate(AllHeaders[i])) return AllHeaders[i];
        return null;
    }

    /// <summary>The value of the most recent <c>[Name=Value]</c> header (or pre-record <c>Name = Value</c> line), or null.</summary>
    internal string? Header(string name)
    {
        string? header = LatestHeader(h => h.IndexOf('=') is int eq && eq > 0 && h.AsSpan(0, eq).Trim().SequenceEqual(name));
        return header?[(header.IndexOf('=') + 1)..].Trim();
    }

    internal string Text(string name) =>
        Fields.TryGetValue(name, out string? value)
            ? value
            : throw new InvalidDataException($"{Path.GetFileName(File)} line {Line}: missing field '{name}'.");

    internal byte[] Hex(string name) => Convert.FromHexString(Text(name));

    internal byte[]? OptionalHex(string name) =>
        Fields.TryGetValue(name, out string? value) ? Convert.FromHexString(value) : null;

    internal int Count => int.Parse(Text("COUNT"));

    public override string ToString() => $"{Path.GetFileName(File)} COUNT={Fields.GetValueOrDefault("COUNT")} (line {Line})";
}

/// <summary>
/// Streams the shared CAVP .rsp/.fax layout: <c>[header]</c> lines, <c>#</c> comments, and
/// <c>key = value</c> fields grouped into records that begin at <c>COUNT</c>. Headers accumulate
/// through the file, so a record sees every header before it and the latest one of a kind wins.
/// </summary>
internal static class RspReader
{
    internal static IEnumerable<RspRecord> Read(string path)
    {
        var headers = new List<string>();
        Dictionary<string, string>? fields = null;
        int recordLine = 0;
        int lineNumber = 0;

        foreach (string raw in File.ReadLines(path))
        {
            lineNumber++;
            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;

            if (line[0] == '[')
            {
                if (fields is not null) { yield return Record(); fields = null; }
                headers.Add(line.TrimStart('[').TrimEnd(']').Trim());
                continue;
            }

            int eq = line.IndexOf('=');
            if (eq <= 0)
                throw new InvalidDataException($"{Path.GetFileName(path)} line {lineNumber}: unexpected '{line}'.");
            string key = line[..eq].Trim();
            string value = line[(eq + 1)..].Trim();

            if (key == "COUNT")
            {
                if (fields is not null) yield return Record();
                fields = new Dictionary<string, string>(StringComparer.Ordinal);
                recordLine = lineNumber;
            }
            else if (fields is null)
            {
                // Fields before the first COUNT are section-level settings.
                headers.Add($"{key}={value}");
                continue;
            }

            if (!fields.TryAdd(key, value))
                throw new InvalidDataException($"{Path.GetFileName(path)} line {lineNumber}: duplicate field '{key}'.");
        }

        if (fields is not null) yield return Record();

        RspRecord Record() => new(path, recordLine, headers, headers.Count, fields!);
    }
}
