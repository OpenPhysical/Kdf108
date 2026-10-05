using System.IO;
using System.Linq;

namespace Kdf108.Test.Support;

/// <summary>Locates checked-in test resources relative to the test project.</summary>
internal static class TestPaths
{
    private static readonly string ProjectRoot = FindProjectRoot();

    internal static string Project => ProjectRoot;

    internal static string Vectors(params string[] parts) =>
        Path.Combine(new[] { ProjectRoot, "res", "vectors" }.Concat(parts).ToArray());

    private static string FindProjectRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !directory.GetFiles("Kdf108.Test.csproj").Any())
            directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate Kdf108.Test.csproj.");
    }
}
