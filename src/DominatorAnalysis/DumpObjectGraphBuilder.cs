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

        var scannedNodes = new List<ObjectNode>();
        var addressToNodeId = new Dictionary<ulong, int>(1_000_000);
        var scannedTypeIdsByKey = new Dictionary<TypeKey, int>();
        var scannedTypeIdsByClrType = new Dictionary<ClrType, int>();
        var scannedTypes = new List<TypeInfo>();
        var stopwatch = Stopwatch.StartNew();

        int rootTypeId = GetOrCreateSyntheticTypeId("[GC Roots]", scannedTypeIdsByKey, scannedTypes);
        int rootId = scannedNodes.Count;
        scannedNodes.Add(new ObjectNode(rootId, 0, rootTypeId, 0));

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

                int typeId = GetOrCreateTypeId(obj.Type, scannedTypeIdsByClrType, scannedTypeIdsByKey, scannedTypes);
                int nodeId = scannedNodes.Count;
                addressToNodeId[obj.Address] = nodeId;
                scannedNodes.Add(new ObjectNode(nodeId, obj.Address, typeId, checked((int)obj.Size)));
                objectCount++;
                totalObjectBytes += checked((long)obj.Size);
                if ((objectCount % 1_000_000) == 0)
                {
                    log.WriteLine(
                        "{0,5:n1}s: Scanned {1:n0} objects, graph bytes {2:n1} MB, types {3:n0}",
                        stopwatch.Elapsed.TotalSeconds,
                        objectCount,
                        totalObjectBytes / 1_000_000.0,
                        scannedTypes.Count);
                }
            }
        }

        log.WriteLine(
            "{0,5:n1}s: Finished object scan. Objects={1:n0} Size={2:n1} MB Types={3:n0}",
            stopwatch.Elapsed.TotalSeconds,
            objectCount,
            totalObjectBytes / 1_000_000.0,
            scannedTypes.Count);

        log.WriteLine("{0,5:n1}s: Adding synthetic GC root edges", stopwatch.Elapsed.TotalSeconds);
        int[] rootChildren = CollectRootChildren(runtimes, addressToNodeId, log);
        log.WriteLine("{0,5:n1}s: Starting reachable reference scan", stopwatch.Elapsed.TotalSeconds);
        ReachableGraphCounts reachable = CountReachableGraph(runtimes, scannedNodes, addressToNodeId, rootId, rootChildren, log, stopwatch);
        log.WriteLine(
            "{0,5:n1}s: Reachable graph counted. ReachableNodes={1:n0} EdgeCount={2:n0}",
            stopwatch.Elapsed.TotalSeconds,
            reachable.ReachableNodeCount,
            reachable.EdgeCount);

        log.WriteLine("{0,5:n1}s: Compacting reachable graph", stopwatch.Elapsed.TotalSeconds);
        CompactGraph compact = CompactReachableGraph(scannedNodes, scannedTypes, rootId, reachable);
        int[] children = AllocateEdgeStorage(compact.Nodes, compact.ChildCounts, isChildStorage: true);
        int[] parents = AllocateEdgeStorage(compact.Nodes, compact.ParentCounts, isChildStorage: false);
        FillReachableEdges(runtimes, scannedNodes, compact, addressToNodeId, rootId, rootChildren, children, parents);
        log.WriteLine(
            "{0,5:n1}s: Graph ready. NodeCount={1:n0} EdgeCount={2:n0}",
            stopwatch.Elapsed.TotalSeconds,
            compact.Nodes.Count,
            reachable.EdgeCount);

        return new ObjectGraph(compact.RootId, compact.Nodes, compact.Types, children, parents);
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

    private static void FillReachableEdges(
        ClrRuntime[] runtimes,
        List<ObjectNode> scannedNodes,
        CompactGraph compact,
        Dictionary<ulong, int> addressToNodeId,
        int scannedRootId,
        int[] scannedRootChildren,
        int[] children,
        int[] parents)
    {
        int[] nextChild = new int[compact.Nodes.Count];
        int[] nextParent = new int[compact.Nodes.Count];
        for (int i = 0; i < compact.Nodes.Count; i++)
        {
            nextChild[i] = compact.Nodes[i].ChildStart;
            nextParent[i] = compact.Nodes[i].ParentStart;
        }

        int compactRootId = compact.RootId;
        for (int i = 0; i < scannedRootChildren.Length; i++)
        {
            int scannedChildId = scannedRootChildren[i];
            int compactChildId = compact.OldToNew[scannedChildId];
            if (compactChildId < 0)
            {
                continue;
            }

            children[nextChild[compactRootId]++] = compactChildId;
            parents[nextParent[compactChildId]++] = compactRootId;
        }

        var uniqueChildren = new HashSet<int>();
        foreach (ClrSegment segment in runtimes.SelectMany(runtime => runtime.Heap.Segments).OrderBy(segment => segment.Start))
        {
            foreach (ClrObject obj in segment.EnumerateObjects())
            {
                if (!addressToNodeId.TryGetValue(obj.Address, out int scannedNodeId))
                {
                    continue;
                }

                int compactNodeId = compact.OldToNew[scannedNodeId];
                if (compactNodeId < 0 || scannedNodeId == scannedRootId)
                {
                    continue;
                }

                uniqueChildren.Clear();
                foreach (ulong childAddress in obj.EnumerateReferenceAddresses(carefully: true, considerDependantHandles: true))
                {
                    if (!addressToNodeId.TryGetValue(childAddress, out int scannedChildId) || !uniqueChildren.Add(scannedChildId))
                    {
                        continue;
                    }

                    int compactChildId = compact.OldToNew[scannedChildId];
                    if (compactChildId < 0)
                    {
                        continue;
                    }

                    children[nextChild[compactNodeId]++] = compactChildId;
                    parents[nextParent[compactChildId]++] = compactNodeId;
                }
            }
        }
    }

    private static ReachableGraphCounts CountReachableGraph(
        ClrRuntime[] runtimes,
        List<ObjectNode> scannedNodes,
        Dictionary<ulong, int> addressToNodeId,
        int rootId,
        int[] rootChildren,
        TextWriter log,
        Stopwatch stopwatch)
    {
        var reachable = new bool[scannedNodes.Count];
        var childCounts = new int[scannedNodes.Count];
        var parentCounts = new int[scannedNodes.Count];
        var queue = new Queue<int>();
        var uniqueChildren = new HashSet<int>();
        long edgeCount = 0;
        long scannedReachableObjects = 0;

        reachable[rootId] = true;
        childCounts[rootId] = rootChildren.Length;
        for (int i = 0; i < rootChildren.Length; i++)
        {
            int childId = rootChildren[i];
            parentCounts[childId]++;
            edgeCount++;
            if (!reachable[childId])
            {
                reachable[childId] = true;
                queue.Enqueue(childId);
            }
        }

        while (queue.Count > 0)
        {
            int scannedNodeId = queue.Dequeue();
            scannedReachableObjects++;
            ObjectNode scannedNode = scannedNodes[scannedNodeId];
            ClrObject obj = GetObject(runtimes, scannedNode.Address);
            if (!obj.IsValid)
            {
                continue;
            }

            uniqueChildren.Clear();
            foreach (ulong childAddress in obj.EnumerateReferenceAddresses(carefully: true, considerDependantHandles: true))
            {
                if (!addressToNodeId.TryGetValue(childAddress, out int scannedChildId) || !uniqueChildren.Add(scannedChildId))
                {
                    continue;
                }

                childCounts[scannedNodeId]++;
                parentCounts[scannedChildId]++;
                edgeCount++;
                if (!reachable[scannedChildId])
                {
                    reachable[scannedChildId] = true;
                    queue.Enqueue(scannedChildId);
                }
            }

            if ((scannedReachableObjects % 500_000) == 0)
            {
                log.WriteLine(
                    "{0,5:n1}s: Counted reachable refs for {1:n0} objects, edges {2:n0}",
                    stopwatch.Elapsed.TotalSeconds,
                    scannedReachableObjects,
                    edgeCount);
            }
        }

        int reachableNodeCount = 0;
        for (int i = 0; i < reachable.Length; i++)
        {
            if (reachable[i])
            {
                reachableNodeCount++;
            }
        }

        return new ReachableGraphCounts(reachable, childCounts, parentCounts, reachableNodeCount, edgeCount);
    }

    private static CompactGraph CompactReachableGraph(
        List<ObjectNode> scannedNodes,
        List<TypeInfo> scannedTypes,
        int scannedRootId,
        ReachableGraphCounts reachable)
    {
        var newTypeIdsByOld = new int[scannedTypes.Count];
        for (int i = 0; i < newTypeIdsByOld.Length; i++)
        {
            newTypeIdsByOld[i] = -1;
        }

        var oldToNew = new int[scannedNodes.Count];
        for (int i = 0; i < oldToNew.Length; i++)
        {
            oldToNew[i] = -1;
        }

        var types = new List<TypeInfo>();
        var nodes = new List<ObjectNode>(reachable.ReachableNodeCount);
        var childCounts = new int[reachable.ReachableNodeCount];
        var parentCounts = new int[reachable.ReachableNodeCount];

        for (int oldNodeId = 0; oldNodeId < scannedNodes.Count; oldNodeId++)
        {
            if (!reachable.Reachable[oldNodeId])
            {
                continue;
            }

            ObjectNode oldNode = scannedNodes[oldNodeId];
            int newTypeId = GetOrCreateCompactedTypeId(oldNode.TypeId, scannedTypes, newTypeIdsByOld, types);
            int newNodeId = nodes.Count;
            oldToNew[oldNodeId] = newNodeId;
            nodes.Add(new ObjectNode(newNodeId, oldNode.Address, newTypeId, oldNode.Size));
            childCounts[newNodeId] = reachable.ChildCounts[oldNodeId];
            parentCounts[newNodeId] = reachable.ParentCounts[oldNodeId];
            types[newTypeId].ExclusiveBytes += oldNode.Size;
            if (oldNodeId != scannedRootId)
            {
                types[newTypeId].ExclusiveCount++;
            }
        }

        return new CompactGraph(oldToNew[scannedRootId], oldToNew, nodes, types, childCounts, parentCounts);
    }

    private static int GetOrCreateCompactedTypeId(int oldTypeId, List<TypeInfo> scannedTypes, int[] newTypeIdsByOld, List<TypeInfo> types)
    {
        int newTypeId = newTypeIdsByOld[oldTypeId];
        if (newTypeId >= 0)
        {
            return newTypeId;
        }

        TypeInfo oldType = scannedTypes[oldTypeId];
        newTypeId = types.Count;
        newTypeIdsByOld[oldTypeId] = newTypeId;
        types.Add(new TypeInfo(newTypeId, oldType.Name, oldType.FullName, oldType.ModuleName, oldType.IsSynthetic));
        return newTypeId;
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

    private sealed class ReachableGraphCounts
    {
        public ReachableGraphCounts(bool[] reachable, int[] childCounts, int[] parentCounts, int reachableNodeCount, long edgeCount)
        {
            Reachable = reachable;
            ChildCounts = childCounts;
            ParentCounts = parentCounts;
            ReachableNodeCount = reachableNodeCount;
            EdgeCount = edgeCount;
        }

        public bool[] Reachable { get; }
        public int[] ChildCounts { get; }
        public int[] ParentCounts { get; }
        public int ReachableNodeCount { get; }
        public long EdgeCount { get; }
    }

    private sealed class CompactGraph
    {
        public CompactGraph(int rootId, int[] oldToNew, List<ObjectNode> nodes, List<TypeInfo> types, int[] childCounts, int[] parentCounts)
        {
            RootId = rootId;
            OldToNew = oldToNew;
            Nodes = nodes;
            Types = types;
            ChildCounts = childCounts;
            ParentCounts = parentCounts;
        }

        public int RootId { get; }
        public int[] OldToNew { get; }
        public List<ObjectNode> Nodes { get; }
        public List<TypeInfo> Types { get; }
        public int[] ChildCounts { get; }
        public int[] ParentCounts { get; }
    }
}
