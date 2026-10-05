using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Kdf108.Test.Support;

namespace Kdf108.Test.Docs;

/// <summary>
/// Every C# block in README.md and docs/ must be a verbatim copy of a <c>#region snippet:name</c>
/// in Snippets.cs (which compiles and runs). Each block is preceded by <c>&lt;!-- snippet: name --&gt;</c>.
/// Set KDF108_UPDATE_SNIPPETS=1 and run this test to rewrite the markdown from the source.
/// </summary>
[TestFixture]
public partial class DocSnippetTests
{
    private static readonly string Repository = Path.GetFullPath(Path.Combine(TestPaths.Project, "..", ".."));

    [GeneratedRegex(@"^[ \t]*#region snippet:(?<name>[\w-]+)\r?\n(?<body>.*?)^[ \t]*#endregion", RegexOptions.Multiline | RegexOptions.Singleline)]
    private static partial Regex Region();

    [GeneratedRegex(@"<!-- snippet: (?<name>[\w-]+) -->\r?\n```csharp\r?\n(?<body>.*?)```", RegexOptions.Singleline)]
    private static partial Regex MarkedBlock();

    [GeneratedRegex(@"```(csharp|cs|c#)\r?\n")]
    private static partial Regex AnyCSharpBlock();

    private static Dictionary<string, string> Sources() =>
        Region().Matches(File.ReadAllText(Path.Combine(TestPaths.Project, "Docs", "Snippets.cs")))
            .ToDictionary(m => m.Groups["name"].Value, m => Dedent(m.Groups["body"].Value));

    private static IEnumerable<string> MarkdownFiles() =>
        new[] { Path.Combine(Repository, "README.md"), Path.Combine(Repository, "index.md"), Path.Combine(Repository, "examples", "README.md") }
            .Concat(Directory.EnumerateFiles(Path.Combine(Repository, "docs"), "*.md", SearchOption.AllDirectories)
                .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}api{Path.DirectorySeparatorChar}", StringComparison.Ordinal)))
            .Where(File.Exists);

    [Test]
    public void EveryCSharpBlockInTheDocsIsACompiledSnippet()
    {
        var sources = Sources();
        bool update = Environment.GetEnvironmentVariable("KDF108_UPDATE_SNIPPETS") == "1";
        var problems = new List<string>();
        foreach (string file in MarkdownFiles())
        {
            string text = File.ReadAllText(file);
            string name = Path.GetRelativePath(Repository, file);
            int marked = MarkedBlock().Matches(text).Count;
            int all = AnyCSharpBlock().Matches(text).Count;
            if (marked != all)
                problems.Add($"{name}: {all - marked} C# block(s) without a <!-- snippet: name --> marker.");

            string rewritten = MarkedBlock().Replace(text, m =>
            {
                string snippet = m.Groups["name"].Value;
                if (!sources.TryGetValue(snippet, out string? source))
                {
                    problems.Add($"{name}: unknown snippet '{snippet}'.");
                    return m.Value;
                }
                if (m.Groups["body"].Value.ReplaceLineEndings("\n") != source)
                    problems.Add($"{name}: snippet '{snippet}' differs from Snippets.cs.");
                return $"<!-- snippet: {snippet} -->\n```csharp\n{source}```";
            });
            if (update && rewritten != text) File.WriteAllText(file, rewritten);
        }

        if (update) problems.RemoveAll(p => p.Contains("differs", StringComparison.Ordinal));
        Assert.That(problems, Is.Empty);
    }

    [Test]
    public void EverySnippetIsUsedSomewhere()
    {
        var used = MarkdownFiles().SelectMany(f => MarkedBlock().Matches(File.ReadAllText(f))).Select(m => m.Groups["name"].Value).ToHashSet();
        Assert.That(Sources().Keys.Where(k => !used.Contains(k)), Is.Empty);
    }

    private static string Dedent(string body)
    {
        var lines = body.ReplaceLineEndings("\n").TrimEnd('\n', ' ').Split('\n');
        int indent = lines.Where(l => l.Trim().Length > 0).Min(l => l.Length - l.TrimStart().Length);
        return string.Join("\n", lines.Select(l => l.Length >= indent ? l[indent..] : l.TrimStart())) + "\n";
    }
}
