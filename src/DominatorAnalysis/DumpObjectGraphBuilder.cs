using Azure.Core;
using Azure.Identity;
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Microsoft.Diagnostics.DominatorAnalysis;

public static class DumpObjectGraphBuilder
{
    public static ObjectGraph BuildFromDump(string dumpPath, TextWriter log = null)
    {
        if (string.IsNullOrWhiteSpace(dumpPath))
        {
            throw new ArgumentException("A dump path is required.", nameof(dumpPath));
        }

        log ??= TextWriter.Null;

        using DataTarget dataTarget = OpenDump(dumpPath);
        ClrRuntime[] runtimes = CreateRuntimes(dataTarget, log);

        var nodes = new List<ObjectNode>();
        var types = new List<TypeInfo>();
        var addressToNodeId = new Dictionary<ulong, int>(1_000_000);
        var typeIdsByKey = new Dictionary<TypeKey, int>();
        var typeIdsByClrType = new Dictionary<ClrType, int>();
        var stopwatch = Stopwatch.StartNew();

        int rootTypeId = GetOrCreateSyntheticTypeId("[GC Roots]", typeIdsByKey, types);
        int rootId = nodes.Count;
        nodes.Add(new ObjectNode(rootId, 0, rootTypeId, 0));

        log.WriteLine("{0,5:n1}s: Starting object scan", stopwatch.Elapsed.TotalSeconds);
        long objectCount = 0;
        long totalObjectBytes = 0;
        foreach (ClrSegment segment in runtimes.SelectMany(runtime => runtime.Heap.Segments).OrderBy(segment => segment.Start))
        {
            foreach (ClrObject obj in segment.EnumerateObjects())
            {
                if (obj.Type is null)
                {
                    continue;
                }

                int typeId = GetOrCreateTypeId(obj.Type, typeIdsByClrType, typeIdsByKey, types);
                int nodeId = nodes.Count;
                addressToNodeId[obj.Address] = nodeId;
                nodes.Add(new ObjectNode(nodeId, obj.Address, typeId, checked((int)obj.Size)));
                types[typeId].ExclusiveBytes += checked((long)obj.Size);
                types[typeId].ExclusiveCount++;
                objectCount++;
                totalObjectBytes += checked((long)obj.Size);
                if ((objectCount % 1_000_000) == 0)
                {
                    log.WriteLine(
                        "{0,5:n1}s: Scanned {1:n0} objects, graph bytes {2:n1} MB, types {3:n0}",
                        stopwatch.Elapsed.TotalSeconds,
                        objectCount,
                        totalObjectBytes / 1_000_000.0,
                        types.Count);
                }
            }
        }

        log.WriteLine(
            "{0,5:n1}s: Finished object scan. Objects={1:n0} Size={2:n1} MB Types={3:n0}",
            stopwatch.Elapsed.TotalSeconds,
            objectCount,
            totalObjectBytes / 1_000_000.0,
            types.Count);

        int[] childCounts = new int[nodes.Count];
        int[] parentCounts = new int[nodes.Count];
        var uniqueChildren = new HashSet<int>();
        log.WriteLine("{0,5:n1}s: Starting reference scan", stopwatch.Elapsed.TotalSeconds);
        long edgeCount = 0;
        long sourceObjectCount = 0;
        foreach (ClrSegment segment in runtimes.SelectMany(runtime => runtime.Heap.Segments).OrderBy(segment => segment.Start))
        {
            foreach (ClrObject obj in segment.EnumerateObjects())
            {
                if (!addressToNodeId.TryGetValue(obj.Address, out int nodeId))
                {
                    continue;
                }

                uniqueChildren.Clear();
                foreach (ulong childAddress in obj.EnumerateReferenceAddresses(carefully: true, considerDependantHandles: true))
                {
                    if (!addressToNodeId.TryGetValue(childAddress, out int childId) || !uniqueChildren.Add(childId))
                    {
                        continue;
                    }

                    childCounts[nodeId]++;
                    parentCounts[childId]++;
                    edgeCount++;
                }

                sourceObjectCount++;
                if ((sourceObjectCount % 500_000) == 0)
                {
                    log.WriteLine(
                        "{0,5:n1}s: Scanned references for {1:n0} objects, edges {2:n0}",
                        stopwatch.Elapsed.TotalSeconds,
                        sourceObjectCount,
                        edgeCount);
                }
            }
        }

        log.WriteLine(
            "{0,5:n1}s: Finished reference scan. EdgeCount={1:n0}",
            stopwatch.Elapsed.TotalSeconds,
            edgeCount);

        log.WriteLine("{0,5:n1}s: Adding synthetic GC root edges", stopwatch.Elapsed.TotalSeconds);
        int[] rootChildren = CollectRootChildren(runtimes, addressToNodeId, log);
        childCounts[rootId] += rootChildren.Length;
        for (int i = 0; i < rootChildren.Length; i++)
        {
            parentCounts[rootChildren[i]]++;
        }

        int[] children = AllocateEdgeStorage(nodes, childCounts, isChildStorage: true);
        int[] parents = AllocateEdgeStorage(nodes, parentCounts, isChildStorage: false);
        int[] nextParent = FillReferenceEdges(runtimes, nodes, addressToNodeId, children, parents);
        FillRootEdges(rootId, rootChildren, nodes, children, parents, nextParent);
        log.WriteLine(
            "{0,5:n1}s: Graph ready. NodeCount={1:n0} EdgeCount={2:n0}",
            stopwatch.Elapsed.TotalSeconds,
            nodes.Count,
            edgeCount + rootChildren.Length);

        return new ObjectGraph(rootId, nodes, types, children, parents);
    }

    private static int[] CollectRootChildren(
        ClrRuntime[] runtimes,
        Dictionary<ulong, int> addressToNodeId,
        TextWriter log)
    {
        var rootedNodes = new HashSet<int>();
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
                            AddRootEdge(obj.Address, addressToNodeId, rootedNodes);
                        }
                    }
                }
            }

            foreach (ClrRoot root in runtimes.SelectMany(runtime => runtime.Heap.EnumerateRoots()))
            {
                if (!root.Object.IsValid)
                {
                    continue;
                }

                AddRootEdge(root.Object.Address, addressToNodeId, rootedNodes);
            }
        }
        catch (Exception ex) when (!(ex is OutOfMemoryException))
        {
            log.WriteLine("[ERROR while processing roots: {0}]", ex.Message);
            log.WriteLine("Continuing with partial root information.");
        }

        int[] result = new int[rootedNodes.Count];
        rootedNodes.CopyTo(result);
        return result;
    }

    private static void AddRootEdge(
        ulong address,
        Dictionary<ulong, int> addressToNodeId,
        HashSet<int> rootedNodes)
    {
        if (address == 0 || !addressToNodeId.TryGetValue(address, out int nodeId))
        {
            return;
        }

        rootedNodes.Add(nodeId);
    }

    private static int[] AllocateEdgeStorage(List<ObjectNode> nodes, int[] counts, bool isChildStorage)
    {
        int total = 0;
        for (int i = 0; i < nodes.Count; i++)
        {
            if (isChildStorage)
            {
                nodes[i].ChildStart = total;
                nodes[i].ChildCount = counts[i];
            }
            else
            {
                nodes[i].ParentStart = total;
                nodes[i].ParentCount = counts[i];
            }

            total += counts[i];
        }

        return new int[total];
    }

    private static int[] FillReferenceEdges(
        ClrRuntime[] runtimes,
        List<ObjectNode> nodes,
        Dictionary<ulong, int> addressToNodeId,
        int[] children,
        int[] parents)
    {
        int[] nextChild = new int[nodes.Count];
        int[] nextParent = new int[nodes.Count];
        for (int i = 0; i < nodes.Count; i++)
        {
            nextChild[i] = nodes[i].ChildStart;
            nextParent[i] = nodes[i].ParentStart;
        }

        var uniqueChildren = new HashSet<int>();
        foreach (ClrSegment segment in runtimes.SelectMany(runtime => runtime.Heap.Segments).OrderBy(segment => segment.Start))
        {
            foreach (ClrObject obj in segment.EnumerateObjects())
            {
                if (!addressToNodeId.TryGetValue(obj.Address, out int nodeId))
                {
                    continue;
                }

                uniqueChildren.Clear();
                foreach (ulong childAddress in obj.EnumerateReferenceAddresses(carefully: true, considerDependantHandles: true))
                {
                    if (!addressToNodeId.TryGetValue(childAddress, out int childId) || !uniqueChildren.Add(childId))
                    {
                        continue;
                    }

                    children[nextChild[nodeId]++] = childId;
                    parents[nextParent[childId]++] = nodeId;
                }
            }
        }

        return nextParent;
    }

    private static void FillRootEdges(int rootId, int[] rootChildren, List<ObjectNode> nodes, int[] children, int[] parents, int[] nextParent)
    {
        int nextChild = nodes[rootId].ChildStart;
        for (int i = 0; i < rootChildren.Length; i++)
        {
            int childId = rootChildren[i];
            children[nextChild++] = childId;
            parents[nextParent[childId]++] = rootId;
        }
    }

    private static int GetOrCreateTypeId(
        ClrType type,
        Dictionary<ClrType, int> typeIdsByClrType,
        Dictionary<TypeKey, int> typeIdsByKey,
        List<TypeInfo> types)
    {
        if (typeIdsByClrType.TryGetValue(type, out int cachedTypeId))
        {
            return cachedTypeId;
        }

        string typeName = type.Name ?? string.Empty;
        string moduleName = type.Module?.Name;
        string fullName = moduleName == null ? typeName : $"{moduleName}!{typeName}";
        var key = new TypeKey(fullName, typeName, moduleName, false);
        if (!typeIdsByKey.TryGetValue(key, out int typeId))
        {
            typeId = types.Count;
            typeIdsByKey.Add(key, typeId);
            types.Add(new TypeInfo(typeId, key.Name, key.FullName, key.ModuleName, false));
        }

        typeIdsByClrType[type] = typeId;
        return typeId;
    }

    private static int GetOrCreateSyntheticTypeId(string fullName, Dictionary<TypeKey, int> typeIdsByKey, List<TypeInfo> types)
    {
        var key = new TypeKey(fullName, fullName, null, true);
        if (!typeIdsByKey.TryGetValue(key, out int typeId))
        {
            typeId = types.Count;
            typeIdsByKey.Add(key, typeId);
            types.Add(new TypeInfo(typeId, key.Name, key.FullName, key.ModuleName, true));
        }

        return typeId;
    }

    private static DataTarget OpenDump(string dumpPath)
    {
        TokenCredential credential = new InteractiveBrowserCredential();
        var cacheOptions = new CacheOptions { UseOSMemoryFeatures = false };
        DataTarget dataTarget = DataTarget.LoadDump(dumpPath, cacheOptions, credential);
        if (dataTarget.DataReader.PointerSize != IntPtr.Size)
        {
            if (IntPtr.Size == 8)
            {
                throw new InvalidOperationException("Opening a 32 bit dump in a 64 bit process.");
            }

            throw new InvalidOperationException("Opening a 64 bit dump in a 32 bit process.");
        }

        if (dataTarget.ClrVersions.Length == 0)
        {
            throw new InvalidOperationException("Could not find a .NET runtime in the process dump.");
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
            catch (Exception ex) when (ex is InvalidDataException || ex is NotSupportedException)
            {
                log.WriteLine(ex.Message);
            }
        }

        if (runtimes.Count == 0)
        {
            throw new InvalidOperationException("Could not open DAC.");
        }

        return runtimes.ToArray();
    }

    private readonly struct TypeKey : IEquatable<TypeKey>
    {
        public TypeKey(string fullName, string name, string moduleName, bool isSynthetic)
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

        public bool Equals(TypeKey other) =>
            IsSynthetic == other.IsSynthetic &&
            string.Equals(FullName, other.FullName, StringComparison.Ordinal) &&
            string.Equals(ModuleName, other.ModuleName, StringComparison.Ordinal);

        public override bool Equals(object obj) => obj is TypeKey other && Equals(other);

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
}
