using System;
using Spectre.Console;

namespace Kdf108.Examples;

/// <summary>The few console helpers every command shares. Commands receive the console by injection so tests can capture it.</summary>
internal static class ConsoleUi
{
    internal static void Header(this IAnsiConsole console, string title) =>
        console.Write(new Rule($"[cyan]{Markup.Escape(title)}[/]").LeftJustified());

    /// <summary>Shows an error. Library messages contain brackets such as "[L]", so they are escaped.</summary>
    internal static int Error(this IAnsiConsole console, Exception ex)
    {
        console.MarkupLine($"[red]Error:[/] {Markup.Escape(ex.Message)}");
        return 1;
    }

    /// <summary>Hex for display. Output is shortened so a demo never prints a whole secret.</summary>
    internal static string Hex(ReadOnlySpan<byte> bytes, int maxBytes = 8) =>
        bytes.Length <= maxBytes ? Convert.ToHexString(bytes) : Convert.ToHexString(bytes[..maxBytes]) + "…";

    internal static Table Table(params (string Name, string Value)[] rows)
    {
        var table = new Table().Border(TableBorder.Rounded).AddColumn("Item").AddColumn("Value");
        foreach (var (name, value) in rows)
            table.AddRow(Markup.Escape(name), Markup.Escape(value));
        return table;
    }
}
