// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Kdf108.Test.Architecture;

[TestFixture]
public sealed class CryptographyDependencyTests
{
    [Test]
    public void SourceTree_BlacklistsSystemSecurityCryptography()
    {
        string repository = FindRepositoryRoot();
        string forbidden = string.Concat("System.Security.", "Cryptography");
        var violations = new List<string>();

        foreach (string area in new[] { "src", "examples", "tests" })
        foreach (string file in Directory.EnumerateFiles(Path.Combine(repository, area), "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ||
                file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                continue;

            if (File.ReadAllText(file).Contains(forbidden, StringComparison.Ordinal))
                violations.Add(Path.GetRelativePath(repository, file));
        }

        Assert.That(violations, Is.Empty,
            "All cryptographic operations must use Bouncy Castle. Forbidden namespace references: " +
            string.Join(", ", violations));
    }

    [Test]
    public void ResolvedPackages_BlacklistSystemSecurityCryptography()
    {
        string repository = FindRepositoryRoot();
        string forbidden = string.Concat("System.Security.", "Cryptography");
        var violations = new List<string>();

        foreach (string assetsFile in Directory.EnumerateFiles(repository, "project.assets.json", SearchOption.AllDirectories))
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(assetsFile));
            foreach (JsonProperty package in document.RootElement.GetProperty("libraries").EnumerateObject())
            {
                if (package.Name.StartsWith(forbidden, StringComparison.OrdinalIgnoreCase))
                    violations.Add($"{Path.GetRelativePath(repository, assetsFile)}: {package.Name}");
            }
        }

        Assert.That(violations, Is.Empty,
            "Resolved package graphs must not contain forbidden cryptography packages: " +
            string.Join(", ", violations));
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !directory.GetFiles("Kdf108.sln").Any()) directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
