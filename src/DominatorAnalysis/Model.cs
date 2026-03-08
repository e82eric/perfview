using System;
using System.Collections.Generic;

namespace Microsoft.Diagnostics.DominatorAnalysis;

public sealed class ObjectGraph
{
    internal ObjectGraph(int rootId, List<ObjectNode> nodes, List<TypeInfo> types, int[] children, int[] parents)
    {
        RootId = rootId;
        Nodes = nodes;
        Types = types;
        Children = children;
        Parents = parents;
    }

    public int RootId { get; }
    public IReadOnlyList<ObjectNode> Nodes { get; }
    public IReadOnlyList<TypeInfo> Types { get; }
    public int[] Children { get; }
    public int[] Parents { get; }
    public int NodeIndexLimit => Nodes.Count;
    public int TypeIndexLimit => Types.Count;

    public ObjectNode GetNode(int nodeId) => Nodes[nodeId];
    public TypeInfo GetType(int typeId) => Types[typeId];
    public ArraySegment<int> GetChildren(int nodeId)
    {
        ObjectNode node = Nodes[nodeId];
        return new ArraySegment<int>(Children, node.ChildStart, node.ChildCount);
    }

    public ArraySegment<int> GetParents(int nodeId)
    {
        ObjectNode node = Nodes[nodeId];
        return new ArraySegment<int>(Parents, node.ParentStart, node.ParentCount);
    }
}

public sealed class ObjectNode
{
    internal ObjectNode(int id, ulong address, int typeId, int size)
    {
        Id = id;
        Address = address;
        TypeId = typeId;
        Size = size;
    }

    public int Id { get; }
    public int Index => Id;
    public ulong Address { get; }
    public int TypeId { get; }
    public int TypeIndex => TypeId;
    public int Size { get; }
    public int ChildStart { get; internal set; }
    public int ChildCount { get; internal set; }
    public int ParentStart { get; internal set; }
    public int ParentCount { get; internal set; }
}

public sealed class TypeInfo
{
    internal TypeInfo(int id, string name, string fullName, string moduleName, bool isSynthetic)
    {
        Id = id;
        Name = name;
        FullName = fullName;
        ModuleName = moduleName;
        IsSynthetic = isSynthetic;
    }

    public int Id { get; }
    public int Index => Id;
    public string Name { get; }
    public string FullName { get; }
    public string ModuleName { get; }
    public bool IsSynthetic { get; }
    public long ExclusiveBytes { get; internal set; }
    public long ExclusiveCount { get; internal set; }
}

public sealed class DominatorTree
{
    internal DominatorTree(int rootId, int[] immediateDominator, List<int>[] children, int[] dfsIn, int[] dfsOut, int[] nodeByDfsOrder, bool[] reachable)
    {
        RootId = rootId;
        ImmediateDominator = immediateDominator;
        Children = children;
        DfsIn = dfsIn;
        DfsOut = dfsOut;
        NodeByDfsOrder = nodeByDfsOrder;
        Reachable = reachable;
    }

    public int RootId { get; }
    public int[] ImmediateDominator { get; }
    public List<int>[] Children { get; }
    public int[] DfsIn { get; }
    public int[] DfsOut { get; }
    public int[] NodeByDfsOrder { get; }
    public bool[] Reachable { get; }
}

public sealed class TypeSummary
{
    internal TypeSummary(int id, string name, string fullName, string moduleName, bool isSynthetic)
    {
        Id = id;
        Name = name;
        FullName = fullName;
        ModuleName = moduleName;
        IsSynthetic = isSynthetic;
    }

    public int Id { get; }
    public int Index => Id;
    public string Name { get; }
    public string FullName { get; }
    public string ModuleName { get; }
    public bool IsSynthetic { get; }
    public long ExclusiveBytes { get; internal set; }
    public long ExclusiveCount { get; internal set; }
    public long RetainedBytes { get; internal set; }
    public long RetainedCount { get; internal set; }
    public long MinimumRetainedBytes { get; internal set; }
    public long MinimumRetainedCount { get; internal set; }
}

public sealed class RetainedSizeResult
{
    internal RetainedSizeResult(long[] retainedBytesByObject, long[] retainedCountByObject, List<TypeSummary> types)
    {
        RetainedBytesByObject = retainedBytesByObject;
        RetainedCountByObject = retainedCountByObject;
        Types = types;
    }

    public long[] RetainedBytesByObject { get; }
    public long[] RetainedCountByObject { get; }
    public IReadOnlyList<TypeSummary> Types { get; }
}
