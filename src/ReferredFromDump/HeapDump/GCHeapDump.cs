using Graphs;
using System.Collections.Generic;
using Address = System.UInt64;
public sealed class GCHeapDump
{
    internal GCHeapDump(MemoryGraph graph)
    {
        MemoryGraph = graph;
        InteropInfo = new InteropInfo();
        AverageCountMultiplier = 1;
        AverageSizeMultiplier = 1;
    }
    public MemoryGraph MemoryGraph { get; internal set; }
    public InteropInfo InteropInfo { get; internal set; }
    public float AverageCountMultiplier { get; internal set; }
    public float AverageSizeMultiplier { get; internal set; }
    public float[] CountMultipliersByType { get; internal set; }
    public DotNetHeapInfo DotNetHeapInfo { get; internal set; }
    public string CollectionLog { get; internal set; }
}
public sealed class InteropInfo
{
    public sealed class RCWInfo
    {
        internal NodeIndex node;
        internal int refCount;
        internal Address addrIUnknown;
        internal Address addrJupiter;
        internal Address addrVTable;
        internal int firstComInf;
        internal int countComInf;
    }
    public sealed class CCWInfo
    {
        internal NodeIndex node;
        internal int refCount;
        internal Address addrIUnknown;
        internal Address addrHandle;
        internal int firstComInf;
        internal int countComInf;
    }
    public sealed class ComInterfaceInfo
    {
        internal bool fRCW;
        internal int owner;
        internal NodeTypeIndex typeID;
        internal Address addrFirstVTable;
        internal Address addrFirstFunc;
    }
    public sealed class InteropModuleInfo
    {
        public Address baseAddress;
        public uint fileSize;
        public uint timeStamp;
        public string fileName;
    }
    private readonly List<RCWInfo> rcws = new List<RCWInfo>();
    private readonly List<CCWInfo> ccws = new List<CCWInfo>();
    private readonly List<ComInterfaceInfo> interfaces = new List<ComInterfaceInfo>();
    private readonly List<InteropModuleInfo> modules = new List<InteropModuleInfo>();
    public int currentRCWCount => rcws.Count;
    public int currentCCWCount => ccws.Count;
    public int currentInterfaceCount => interfaces.Count;
    public void AddRCW(RCWInfo rcwInfo) => rcws.Add(rcwInfo);
    public void AddCCW(CCWInfo ccwInfo) => ccws.Add(ccwInfo);
    public void AddComInterface(ComInterfaceInfo interfaceInfo) => interfaces.Add(interfaceInfo);
    public void AddModule(InteropModuleInfo moduleInfo) => modules.Add(moduleInfo);
    public bool InteropInfoExists() => rcws.Count != 0 || ccws.Count != 0;
}
