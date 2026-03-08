#nullable enable
using Microsoft.Diagnostics.DominatorAnalysis;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

internal static class Program
{
    private const long OneMegabyte = 1024 * 1024;

    private static int Main(string[] args)
    {
        try
        {
            Options options = Options.Parse(args);
            using TextWriter log = Console.Error;
            IReadOnlyList<TypeSummary> summaries = LoadDump(options.DumpPath, log);

            PrintTypeSummary(summaries, options.IncludeSynthetic);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static IReadOnlyList<TypeSummary> LoadDump(string dumpPath, TextWriter log)
    {
        string extension = Path.GetExtension(dumpPath);
        if (extension.Equals(".dmp", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".hdmp", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".mdmp", StringComparison.OrdinalIgnoreCase))
        {
            ObjectGraph graph = DumpObjectGraphBuilder.BuildFromDump(dumpPath, log);
            DominatorTree dominatorTree = LengauerTarjanDominator.Compute(graph, graph.RootId);
            RetainedSizeResult retained = RetainedSizeAnalyzer.Compute(graph, dominatorTree);
            return retained.Types;
        }

        throw new ArgumentException($"Unsupported input file '{dumpPath}'. Expected a .dmp, .hdmp, or .mdmp.");
    }

    private static void PrintTypeSummary(IReadOnlyList<TypeSummary> summaries, bool includeSynthetic)
    {
        Console.WriteLine(
            $"{PadLeft("ExclusiveBytes", 16)} {PadLeft("ExclusiveCount", 16)} {PadLeft("MinRetainedBytes", 16)} {PadLeft("MinRetainedCount", 16)}  Type");

        IEnumerable<TypeSummary> rows = summaries
            .Where(summary => includeSynthetic || !summary.IsSynthetic)
            .Where(summary => summary.MinimumRetainedBytes >= OneMegabyte)
            .OrderByDescending(summary => summary.MinimumRetainedBytes)
            .ThenByDescending(summary => summary.ExclusiveBytes)
            .ThenBy(summary => summary.FullName, StringComparer.OrdinalIgnoreCase);

        foreach (TypeSummary summary in rows)
        {
            Console.WriteLine(
                $"{PadLeft(FormatNumber(summary.ExclusiveBytes), 16)} {PadLeft(FormatNumber(summary.ExclusiveCount), 16)} {PadLeft(FormatNumber(summary.MinimumRetainedBytes), 16)} {PadLeft(FormatNumber(summary.MinimumRetainedCount), 16)}  {GetDisplayName(summary)}");
        }
    }

    private static string FormatNumber(long value) => value.ToString("N0", CultureInfo.InvariantCulture);

    private static string PadLeft(string value, int width) => value.PadLeft(width, ' ');

    private static string GetDisplayName(TypeSummary summary)
    {
        if (summary.IsSynthetic)
        {
            return summary.FullName;
        }

        string typeName = string.IsNullOrEmpty(summary.Name) ? summary.FullName : summary.Name;
        int lastDot = typeName.LastIndexOf('.');
        if (lastDot < 0)
        {
            return typeName;
        }

        return typeName.Substring(0, lastDot) + "+" + typeName.Substring(lastDot + 1);
    }

    private sealed class Options
    {
        public string DumpPath { get; private set; } = "";
        public bool IncludeSynthetic { get; private set; }

        public static Options Parse(string[] args)
        {
            if (args.Length < 1)
            {
                throw new ArgumentException(
                    "Usage: ReferredFromDump <dump-path> [--include-synthetic]");
            }

            var options = new Options
            {
                DumpPath = args[0]
            };

            for (int i = 1; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--include-synthetic":
                        options.IncludeSynthetic = true;
                        break;
                    default:
                        throw new ArgumentException($"Unknown argument '{args[i]}'.");
                }
            }

            options.DumpPath = Path.GetFullPath(options.DumpPath);
            return options;
        }
    }

}
