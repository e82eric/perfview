using Azure.Core;
using Azure.Identity;
using Graphs;
using Microsoft.Diagnostics.Runtime;
using System.Collections.Generic;
using System.IO;
using System.Linq;
namespace Microsoft.Diagnostics.CompactTypeGraph;
public static class CompactTypeGraphBuilder
{
    public static CompactTypeGraph BuildFromMemoryDump(string dumpPath, TextWriter log = null, CompactTypeGraphOptions options = null)
    {
        if (string.IsNullOrWhiteSpace(dumpPath))
        {
            throw new System.ArgumentException("A dump path is required.", nameof(dumpPath));
        }
        options ??= new CompactTypeGraphOptions();
        log ??= TextWriter.Null;
        using DataTarget dataTarget = OpenDump(dumpPath);
        ClrRuntime[] runtimes = CreateRuntimes(dataTarget, log);
        var keysToIds = new Dictionary<AggregateNodeKey, int>();
        var nodes = new List<CompactTypeGraphNode>();
        var edgesByKey = new Dictionary<long, CompactTypeGraphEdge>();
        var uniqueTargetIds = new HashSet<int>();
        var rootedObjects = new HashSet<ulong>();
        int dotNetRootId = GetOrCreateSyntheticNodeId(Bracket(RootNames.DotNetRootsTitle), keysToIds, nodes);
        foreach (ClrSegment segment in runtimes.SelectMany(runtime => runtime.Heap.Segments).OrderBy(segment => segment.Start))
        {
            foreach (ClrObject obj in segment.EnumerateObjects())
            {
                if (obj.Type is null)
                {
                    continue;
                }
                int sourceId = GetOrCreateTypeNodeId(obj.Type, keysToIds, nodes);
                CompactTypeGraphNode sourceNode = nodes[sourceId];
                sourceNode.NodeCount++;
                sourceNode.TotalSizeBytes += checked((long)obj.Size);
                uniqueTargetIds.Clear();
                foreach (ulong childAddress in obj.EnumerateReferenceAddresses(carefully: true, considerDependantHandles: true))
                {
                    ClrObject child = GetObject(runtimes, childAddress);
                    if (!child.IsValid || child.Type is null)
                    {
                        continue;
                    }
                    int targetId = GetOrCreateTypeNodeId(child.Type, keysToIds, nodes);
                    AddEdge(edgesByKey, nodes, sourceId, targetId, checked((long)child.Size), uniqueTargetIds.Add(targetId));
                }
            }
        }
        if (options.PreserveSyntheticNodes)
        {
            AddSyntheticRootEdges(dataTarget, runtimes, dotNetRootId, keysToIds, nodes, edgesByKey, rootedObjects, log);
        }
        return CreateCompactGraph(nodes, edgesByKey, dotNetRootId);
    }
    private static CompactTypeGraph CreateCompactGraph(List<CompactTypeGraphNode> nodes, Dictionary<long, CompactTypeGraphEdge> edgesByKey, int rootNodeId)
    {
        var edges = new List<CompactTypeGraphEdge>(edgesByKey.Values);
        edges.Sort((left, right) =>
        {
            int fromComparison = left.FromNodeId.CompareTo(right.FromNodeId);
            return fromComparison != 0 ? fromComparison : left.ToNodeId.CompareTo(right.ToNodeId);
        });
        return new CompactTypeGraph(nodes, edges, rootNodeId);
    }
    private static DataTarget OpenDump(string dumpPath)
    {
        TokenCredential credential = new InteractiveBrowserCredential();
        var cacheOptions = new CacheOptions { UseOSMemoryFeatures = false };
        DataTarget dataTarget = DataTarget.LoadDump(dumpPath, cacheOptions, credential);
        if (dataTarget.DataReader.PointerSize != System.IntPtr.Size)
        {
            if (System.IntPtr.Size == 8)
            {
                throw new System.InvalidOperationException("Opening a 32 bit dump in a 64 bit process.");
            }
            throw new System.InvalidOperationException("Opening a 64 bit dump in a 32 bit process.");
        }
        if (dataTarget.ClrVersions.Length == 0)
        {
            throw new System.InvalidOperationException("Could not find a .NET runtime in the process dump.");
        }
        return dataTarget;
    }
    private static ClrRuntime[] CreateRuntimes(DataTarget dataTarget, TextWriter log)
    {
        var runtimes = new List<ClrRuntime>();
        log.WriteLine("Enumerating over {0} detected runtimes...", dataTarget.ClrVersions.Length);
        foreach (ClrInfo clr in dataTarget.ClrVersions)
        {
            log.WriteLine("Creating Runtime access object for runtime {0}.", clr.Version);
            try
            {
                runtimes.Add(clr.CreateRuntime());
            }
            catch (System.Exception ex) when (ex is System.IO.InvalidDataException || ex is System.NotSupportedException)
            {
                log.WriteLine(ex.Message);
            }
        }
        if (runtimes.Count == 0)
        {
            throw new System.InvalidOperationException("Could not open DAC.");
        }
        return runtimes.ToArray();
    }
    private static void AddSyntheticRootEdges(
        DataTarget dataTarget,
        ClrRuntime[] runtimes,
        int dotNetRootId,
        Dictionary<AggregateNodeKey, int> keysToIds,
        List<CompactTypeGraphNode> nodes,
        Dictionary<long, CompactTypeGraphEdge> edgesByKey,
        HashSet<ulong> rootedObjects,
        TextWriter log)
    {
        try
        {
            foreach (ClrModule module in runtimes.SelectMany(runtime => runtime.EnumerateModules()))
            {
                ClrRuntime runtime = module.AppDomain.Runtime;
                foreach (var item in module.EnumerateTypeDefToMethodTableMap())
                {
                    ClrType type = runtime.GetTypeByMethodTable(item.MethodTable);
                    if (type is null)
                    {
                        continue;
                    }
                    foreach (ClrStaticField field in type.StaticFields.Where(staticField => staticField.IsObjectReference))
                    {
                        foreach (ClrAppDomain domain in runtime.AppDomains)
                        {
                            ClrObject obj = field.ReadObject(domain);
                            if (!obj.IsValid || obj.Type is null)
                            {
                                continue;
                            }
                            if (!obj.Type.ContainsPointers && obj.Size <= 0x1000)
                            {
                                continue;
                            }
                            if (!rootedObjects.Add(obj.Address))
                            {
                                continue;
                            }
                            int staticVarsId = GetOrCreateSyntheticNodeId(Bracket(RootNames.StaticVarsRootTitle), keysToIds, nodes);
                            int namedRootId = GetOrCreateSyntheticNodeId(Bracket($"{RootNames.StaticVarPrefix} {field.ContainingType?.Name}.{field.Name}"), keysToIds, nodes);
                            int targetId = GetOrCreateTypeNodeId(obj.Type, keysToIds, nodes);
                            AddEdge(edgesByKey, nodes, dotNetRootId, staticVarsId, 0, false);
                            AddEdge(edgesByKey, nodes, staticVarsId, namedRootId, 0, false);
                            AddEdge(edgesByKey, nodes, namedRootId, targetId, checked((long)obj.Size), false);
                        }
                    }
                }
            }
            foreach (ClrRoot root in runtimes.SelectMany(runtime => runtime.Heap.EnumerateRoots()))
            {
                if (!root.Object.IsValid || root.Object.Type is null)
                {
                    continue;
                }
                if (!rootedObjects.Add(root.Object.Address))
                {
                    continue;
                }
                int categoryId = GetOrCreateSyntheticNodeId(Bracket(GetRootCategoryTitle(root.RootKind, root.IsPinned)), keysToIds, nodes);
                int targetId = GetOrCreateTypeNodeId(root.Object.Type, keysToIds, nodes);
                AddEdge(edgesByKey, nodes, dotNetRootId, categoryId, 0, false);
                AddEdge(edgesByKey, nodes, categoryId, targetId, checked((long)root.Object.Size), false);
            }
        }
        catch (System.Exception ex) when (!(ex is System.OutOfMemoryException))
        {
            log.WriteLine("[ERROR while processing roots: {0}]", ex.Message);
            log.WriteLine("Continuing without complete root information");
        }
    }
    private static string GetRootCategoryTitle(ClrRootKind kind, bool pinned)
    {
        if (pinned && kind == ClrRootKind.Stack)
        {
            return RootNames.PinnedLocalVarsRootTitle;
        }
        switch (kind)
        {
            case ClrRootKind.Stack:
                return RootNames.LocalVarsRootTitle;
            case ClrRootKind.RefCountedHandle:
                return RootNames.COMWinRTRootTitle;
            case ClrRootKind.FinalizerQueue:
                return RootNames.FinalizerQueueRootTitle;
            case ClrRootKind.StrongHandle:
                return RootNames.StrongHandleRootTitle;
            case ClrRootKind.PinnedHandle:
                return RootNames.PinnedHandleRootTitle;
            case ClrRootKind.AsyncPinnedHandle:
                return RootNames.AsyncPinnedHandleRootTitle;
            case ClrRootKind.SizedRefHandle:
                return RootNames.SizedRefHandleRootTitle;
            case ClrRootKind.None:
                return "None";
            default:
                return RootNames.OtherRootsTitle;
        }
    }
    private static int GetOrCreateAggregateNodeId(
        MemoryGraph graph,
        Node node,
        NodeType type,
        CompactTypeGraphOptions options,
        Dictionary<AggregateNodeKey, int> keysToIds,
        List<CompactTypeGraphNode> nodes)
    {
        bool isSynthetic = options.PreserveSyntheticNodes && IsSyntheticNode(graph, node, type, options);
        var key = new AggregateNodeKey(type.FullName, type.Name, type.ModuleName, isSynthetic);
        if (!keysToIds.TryGetValue(key, out int nodeId))
        {
            nodeId = nodes.Count;
            keysToIds.Add(key, nodeId);
            nodes.Add(new CompactTypeGraphNode(nodeId, key.Name, key.FullName, key.ModuleName, key.IsSynthetic));
        }
        return nodeId;
    }
    private static int GetOrCreateTypeNodeId(ClrType type, Dictionary<AggregateNodeKey, int> keysToIds, List<CompactTypeGraphNode> nodes)
    {
        string typeName = type.Name ?? string.Empty;
        string moduleName = type.Module?.Name;
        string fullName = moduleName == null ? typeName : $"{moduleName}!{typeName}";
        var key = new AggregateNodeKey(fullName, typeName, moduleName, false);
        if (!keysToIds.TryGetValue(key, out int nodeId))
        {
            nodeId = nodes.Count;
            keysToIds.Add(key, nodeId);
            nodes.Add(new CompactTypeGraphNode(nodeId, key.Name, key.FullName, key.ModuleName, false));
        }
        return nodeId;
    }
    private static int GetOrCreateSyntheticNodeId(string fullName, Dictionary<AggregateNodeKey, int> keysToIds, List<CompactTypeGraphNode> nodes)
    {
        var key = new AggregateNodeKey(fullName, fullName, null, true);
        if (!keysToIds.TryGetValue(key, out int nodeId))
        {
            nodeId = nodes.Count;
            keysToIds.Add(key, nodeId);
            nodes.Add(new CompactTypeGraphNode(nodeId, key.Name, key.FullName, key.ModuleName, true));
        }
        return nodeId;
    }
    private static bool IsSyntheticNode(MemoryGraph graph, Node node, NodeType type, CompactTypeGraphOptions options)
    {
        if (options.IsSyntheticNode != null)
        {
            return options.IsSyntheticNode(graph, node, type);
        }
        return graph.GetAddress(node.Index) == 0;
    }
    private static void AddEdge(
        Dictionary<long, CompactTypeGraphEdge> edgesByKey,
        List<CompactTypeGraphNode> nodes,
        int sourceId,
        int targetId,
        long targetSize,
        bool sourceNodeWasNewForTarget)
    {
        long edgeKey = MakeEdgeKey(sourceId, targetId);
        if (!edgesByKey.TryGetValue(edgeKey, out CompactTypeGraphEdge edge))
        {
            edge = new CompactTypeGraphEdge(sourceId, targetId);
            edgesByKey.Add(edgeKey, edge);
        }
        edge.ReferenceCount++;
        edge.RawReferencedSizeBytes += targetSize;
        if (sourceNodeWasNewForTarget)
        {
            edge.SourceNodeCount++;
        }
        nodes[sourceId].RawOutgoingReferenceCount++;
        nodes[targetId].RawIncomingReferenceCount++;
    }
    private static ClrObject GetObject(ClrRuntime[] runtimes, ulong address)
    {
        if (address == 0)
        {
            return default;
        }
        if (runtimes.Length == 1)
        {
            return runtimes[0].Heap.GetObject(address);
        }
        foreach (ClrRuntime runtime in runtimes)
        {
            ClrObject obj = runtime.Heap.GetObject(address);
            if (obj.IsValid)
            {
                return obj;
            }
        }
        return default;
    }
    private static long MakeEdgeKey(int fromId, int toId) => ((long)fromId << 32) | (uint)toId;
    private static string Bracket(string value) => $"[{value}]";
    private readonly struct AggregateNodeKey : System.IEquatable<AggregateNodeKey>
    {
        public AggregateNodeKey(string fullName, string name, string moduleName, bool isSynthetic)
        {
            FullName = fullName ?? string.Empty;
            Name = name ?? string.Empty;
            ModuleName = moduleName;
            IsSynthetic = isSynthetic;
        }
        public string FullName { get; }
        public string Name { get; }
        public string ModuleName { get; }
        public bool IsSynthetic { get; }
        public bool Equals(AggregateNodeKey other) =>
            IsSynthetic == other.IsSynthetic &&
            string.Equals(FullName, other.FullName, System.StringComparison.Ordinal) &&
            string.Equals(ModuleName, other.ModuleName, System.StringComparison.Ordinal);
        public override bool Equals(object obj) => obj is AggregateNodeKey other && Equals(other);
        public override int GetHashCode()
        {
            unchecked
            {
                int hash = 17;
                hash = (hash * 31) + (FullName?.GetHashCode() ?? 0);
                hash = (hash * 31) + (ModuleName?.GetHashCode() ?? 0);
                hash = (hash * 31) + IsSynthetic.GetHashCode();
                return hash;
            }
        }
    }
    private static class RootNames
    {
        public const string DotNetRootsTitle = ".NET Roots";
        public const string StaticVarsRootTitle = "static vars";
        public const string StaticVarPrefix = "static var";
        public const string LocalVarsRootTitle = "local vars";
        public const string PinnedLocalVarsRootTitle = "Pinned local vars";
        public const string COMWinRTRootTitle = "COM/WinRT Objects";
        public const string OtherRootsTitle = "other roots";
        public const string FinalizerQueueRootTitle = "FinalizerQueue";
        public const string StrongHandleRootTitle = "StrongHandle";
        public const string PinnedHandleRootTitle = "PinnedHandle";
        public const string AsyncPinnedHandleRootTitle = "AsyncPinnedHandle";
        public const string SizedRefHandleRootTitle = "SizedRefHandle";
    }
}
