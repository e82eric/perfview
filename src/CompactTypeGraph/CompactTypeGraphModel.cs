using System;
using System.Collections.Generic;

namespace Microsoft.Diagnostics.CompactTypeGraph;

public sealed class CompactTypeGraph
{
    internal CompactTypeGraph(List<CompactTypeGraphNode> nodes, List<CompactTypeGraphEdge> edges, int rootNodeId)
    {
        Nodes = nodes;
        Edges = edges;
        RootNodeId = rootNodeId;

        var incoming = new List<CompactTypeGraphEdge>[nodes.Count];
        var outgoing = new List<CompactTypeGraphEdge>[nodes.Count];
        foreach (CompactTypeGraphEdge edge in edges)
        {
            (incoming[edge.ToNodeId] ??= new List<CompactTypeGraphEdge>()).Add(edge);
            (outgoing[edge.FromNodeId] ??= new List<CompactTypeGraphEdge>()).Add(edge);
        }

        IncomingEdges = incoming;
        OutgoingEdges = outgoing;
    }

    public IReadOnlyList<CompactTypeGraphNode> Nodes { get; }

    public IReadOnlyList<CompactTypeGraphEdge> Edges { get; }

    public int RootNodeId { get; }

    public IReadOnlyList<CompactTypeGraphEdge>[] IncomingEdges { get; }

    public IReadOnlyList<CompactTypeGraphEdge>[] OutgoingEdges { get; }

    public CompactTypeGraphNode GetNode(int nodeId) => Nodes[nodeId];

    public IReadOnlyList<CompactTypeGraphEdge> GetIncomingEdges(int nodeId) =>
        IncomingEdges[nodeId] ?? Array.Empty<CompactTypeGraphEdge>();

    public IReadOnlyList<CompactTypeGraphEdge> GetOutgoingEdges(int nodeId) =>
        OutgoingEdges[nodeId] ?? Array.Empty<CompactTypeGraphEdge>();
}

public sealed class CompactTypeGraphNode
{
    internal CompactTypeGraphNode(int id, string name, string fullName, string moduleName, bool isSynthetic)
    {
        Id = id;
        Name = name;
        FullName = fullName;
        ModuleName = moduleName;
        IsSynthetic = isSynthetic;
    }

    public int Id { get; }

    public string Name { get; }

    public string FullName { get; }

    public string ModuleName { get; }

    public bool IsSynthetic { get; }

    public long NodeCount { get; internal set; }

    public long TotalSizeBytes { get; internal set; }

    public long RawIncomingReferenceCount { get; internal set; }

    public long RawOutgoingReferenceCount { get; internal set; }

    public override string ToString() => FullName;
}

public sealed class CompactTypeGraphEdge
{
    internal CompactTypeGraphEdge(int fromNodeId, int toNodeId)
    {
        FromNodeId = fromNodeId;
        ToNodeId = toNodeId;
    }

    public int FromNodeId { get; }

    public int ToNodeId { get; }

    public long ReferenceCount { get; internal set; }

    public long SourceNodeCount { get; internal set; }

    public long RawReferencedSizeBytes { get; internal set; }
}

public sealed class CompactTypeGraphOptions
{
    public bool PreserveSyntheticNodes { get; set; } = true;

    public Func<Graphs.MemoryGraph, Graphs.Node, Graphs.NodeType, bool> IsSyntheticNode { get; set; }
}
