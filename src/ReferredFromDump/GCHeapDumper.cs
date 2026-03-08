using Microsoft.Diagnostics.Symbols;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Clr;
using Graphs;
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using Address = System.UInt64;
using Microsoft.Diagnostics.Utilities;
using Microsoft.Diagnostics.HeapDump;
using Azure.Core;
using Azure.Identity;

/// <summary>
/// GCHeapDumper contains the transient state that needs to be tracked only WHILE the heap is being dumped.
/// </summary>
public class GCHeapDumper
{
    /// <summary>
    /// Create a dumper.   Add options to it, and then call 'DumpFromLiveHeap' or 'DumpHeapFromProcessDump'
    /// to dump a heap.  
    /// </summary>
    /// <param name="log"></param>
    public GCHeapDumper(TextWriter log)
    {
        m_origLog = log;
        SymbolsAuthTokenCredential = new InteractiveBrowserCredential();
        m_copyOfLog = new StringWriter();
        m_log = new TeeTextWriter(m_copyOfLog, m_origLog);

        MaxDumpCountK = 250;
    }



    /// <summary>
    /// Dump from a process memory dump and return the in-memory heap dump without serializing it.
    /// </summary>
    public GCHeapDump DumpHeapFromProcessDump(string processDumpFile)
    {
        DumpHeapFromProcessDumpWorker(processDumpFile);
        return m_gcHeapDump;
    }

    private void DumpHeapFromProcessDumpWorker(string processDumpFile)
    {
        m_sw = Stopwatch.StartNew();
        m_gcHeapDump = new GCHeapDump((MemoryGraph)null);

        using (DataTarget dataTarget = InitializeClrRuntime(processDumpFile, out ClrRuntime[] runtimes))
        {
            DumpDotNetHeapData(dataTarget, runtimes);
            FinalizeDump(logLiveStats: false);
        }
    }

    private DataTarget InitializeClrRuntime(string processDumpFile, out ClrRuntime[] result)
    {
        List<ClrRuntime> runtimes = new List<ClrRuntime>();

        DataTarget dataTarget;
        CacheOptions cacheOptions = new CacheOptions()
        {
            UseOSMemoryFeatures = false // disable AWE
        };

        dataTarget = DataTarget.LoadDump(processDumpFile, cacheOptions, SymbolsAuthTokenCredential);

        if (dataTarget.DataReader.PointerSize != IntPtr.Size)
        {
            if (IntPtr.Size == 8)
            {
                throw new HeapDumpException("Opening a 32 bit dump in a 64 bit process.", HR.Opening32BitDumpIn64BitProcess);
            }
            else
            {
                throw new HeapDumpException("Opening a 64 bit dump in a 32 bit process.", HR.Opening64BitDumpIn32BitProcess);
            }
        }

        if (dataTarget.ClrVersions.Length == 0)
        {
            throw new HeapDumpException("Could not find a .NET Runtime in the process dump " + processDumpFile, HR.NoDotNetRuntimeFound);
        }

        m_log.WriteLine("Enumerating over {0} detected runtimes...", dataTarget.ClrVersions.Length);
        var symbolReader = new SymbolReader(m_log, null);
        if (symbolReader.SymbolPath.Length == 0)
            symbolReader.SymbolPath = SymbolPath.MicrosoftSymbolServerPath;

        foreach (ClrInfo clr in dataTarget.ClrVersions)
        {
            m_log.WriteLine("Creating Runtime access object for runtime {0}.", clr.Version);

            try
            {
                runtimes.Add(clr.CreateRuntime());
            }
            catch (InvalidDataException ex)
            {
                m_log.WriteLine(ex.Message);
            }
            catch (NotSupportedException ex)
            {
                m_log.WriteLine(ex.Message);
            }
        }

        if (runtimes.Count == 0)
            throw new HeapDumpException("Could not open DAC", HR.CouldNotAccessDac);

        result = runtimes.ToArray();
        return dataTarget;
    }
    /// <summary>
    /// The maximum number of heap objects to dump(in kiloObjects).  Above this number we start sampling to keep
    /// file size and viewer processing time under control.  
    /// </summary>
    public int MaxDumpCountK;

    /// <summary>
    /// This number tells us when to stop even looking at the heap (otherwise we do make a graph and then sample from that)
    /// </summary>
    public int MaxNodeCountK;



    /// <summary>
    /// The token credential to use for symbol server authentication.
    /// </summary>
    public TokenCredential SymbolsAuthTokenCredential;
    // output properties
    /// <summary>
    /// The number of bad objects encountered during the dump 
    /// </summary>
    public int BadObjectCount { get; private set; }

    /// <summary>
    /// Dump a heap associated with 'runtime' to  the m_gcHeapDump.  If 'debugProcess' is non-null use it
    /// to gather symbolic information on the roots.  
    /// 
    /// Dump tries to aggressively Detach from debugProcess (so if we are killed, it does 
    /// not bring down the debuggee).   When we have detached, we also null out debugProcess, 
    /// since it is now pretty useless.   
    /// 
    /// The resulting heap dump is in the m_gcHeapDump.MemoryGraph variable. 
    /// </summary>
    private void DumpDotNetHeapData(DataTarget dataTarget, ClrRuntime[] runtimes)
    {
        // We retry if we run out of memory with smaller MaxNodeCount.  
        for (double retryScale = 1; ; retryScale = retryScale * 1.5)
        {
            try
            {
                var curHeapSize = GC.GetTotalMemory(false);
                m_log.WriteLine("DumpDotNetHeapData: Heap Size {0:n0} MB", curHeapSize / 1000000.0);
                DumpDotNetHeapDataWorker(dataTarget, runtimes, retryScale);
                return;
            }
            catch (OutOfMemoryException e)
            {
                // Give up after trying a few times.  
                if (retryScale > 10)
                {
                    throw;
                }

                foreach (ClrRuntime runtime in runtimes)
                    runtime.FlushCachedData();

                // Keep caching types since it's used in a Dictionary, maybe rethink that in the future
                dataTarget.CacheOptions.CacheTypes = true;
                dataTarget.CacheOptions.CacheMethods = false;
                dataTarget.CacheOptions.CacheFields = false;

                dataTarget.CacheOptions.CacheTypeNames = StringCaching.None;
                dataTarget.CacheOptions.CacheMethodNames = StringCaching.None;
                dataTarget.CacheOptions.CacheFieldNames = StringCaching.None;

                // Thow away the log that we will put into the .gcdump file for this first round. 
                m_copyOfLog = new StringWriter();
                m_log = new TeeTextWriter(m_copyOfLog, m_origLog);

                long beforeGCMemSize = GC.GetTotalMemory(false);
                m_gcHeapDump.MemoryGraph = null;        // Free most of the memory.  
                long afterGCMemSize = GC.GetTotalMemory(true);
                m_log.WriteLine("{0,5:f1}s: WARNING: Hit and Out of Memory Condition, retrying with a smaller MaxObjectCount", m_sw.Elapsed.TotalSeconds);
                m_log.WriteLine("Stack: {0}", e.StackTrace);

                m_log.WriteLine("{0,5:f1}s: Dumper heap usage before {1:n0} MB after {2:n0} MB",
                    m_sw.Elapsed.TotalSeconds, beforeGCMemSize / 1000000.0, afterGCMemSize / 1000000.0);

            }
        }
    }

    private void DumpDotNetHeapDataWorker(DataTarget dataTarget, ClrRuntime[] runtimes, double retryScale)
    {
        IEnumerable<ClrSegment> allSegments = runtimes.SelectMany(r => r.Heap.Segments).OrderBy(r => r.Start);

        m_children = new GrowableArray<NodeIndex>(2000);
        m_graphTypeIdxForArrayType = new Dictionary<string, NodeTypeIndex>(100);
        m_typeIdxToGraphIdx = new GrowableArray<int>();

        m_gotDotNetData = true;
        m_copyOfLog.GetStringBuilder().Length = 0;  // Restart the copy

        m_log.WriteLine("Dumping GC heap, This process is a {0} bit process on a {1} bit OS",
            EnvironmentUtilities.Is64BitProcess ? "64" : "32",
            EnvironmentUtilities.Is64BitOperatingSystem ? "64" : "32");
        m_log.WriteLine("{0,5:f1}s: Starting heap dump {1}", m_sw.Elapsed.TotalSeconds, DateTime.Now);

        ulong totalGCSize = (ulong)allSegments.Sum(s => (long)s.Length);
        if (MaxDumpCountK != 0 && MaxDumpCountK < 10)   // Having fewer than 10K is probably wrong.
            MaxDumpCountK = 10;

        m_log.WriteLine("{0,5:f1}s: Size of heap = {1:f3} GB", m_sw.Elapsed.TotalSeconds, ((double)totalGCSize) / 1000000000.0);

        // We have an overhead of about 52 bytes per object (24 for the hash table, 28 for the rest)
        // we have 1GB in a 32 bit process 
        m_maxNodeCount = 1000000000 / 52;       // 20 Meg objects;
        if (EnvironmentUtilities.Is64BitOperatingSystem)
        {
            m_maxNodeCount *= 3;                // We have 4GB instead of 2GB, so we 3GB instead of 1GB available for us to use in 32 bit processes = 60Meg objects
        }

        // On 64 bit process we are limited by the fact that the graph node is in a MemoryStream and its byte array is limited to 2 gig.  Most objects will
        // be represented by 10 bytes in this array and we round this up to 16 = 128Meg
        if (EnvironmentUtilities.Is64BitProcess)
        {
            m_maxNodeCount = int.MaxValue / 16 - 11;      // Limited to 128Meg objects.  (We are limited by the size of the stream)
            m_log.WriteLine("In a 64 bit process.  Increasing the max node count to {0:f1} Meg", m_maxNodeCount / 1000000.0);
        }
        m_log.WriteLine("Implicitly limit the number of nodes to {0:f1} Meg to avoid arrays that are too large", m_maxNodeCount / 1000000.0);

        // Can force it smaller in case our estimate is not good enough.  
        var explicitMax = MaxNodeCountK * 1000;
        if (0 < explicitMax)
        {
            m_maxNodeCount = Math.Min(m_maxNodeCount, explicitMax);
            m_log.WriteLine("Explicit object count maximum {0:n0}, resulting max {1:n0}", explicitMax, m_maxNodeCount);
        }

        if (retryScale != 1)
        {
            m_maxNodeCount = (int)(m_maxNodeCount / retryScale);
            m_log.WriteLine("We are retrying the dump so we scale the max by {0} to the value {1}", retryScale, m_maxNodeCount);
        }

        // We assume that object on average are 8 object pointers.      
        int estimatedObjectCount = (int)(totalGCSize / ((uint)(8 * IntPtr.Size)));
        m_log.WriteLine("Estimated number of objects = {0:n0}", estimatedObjectCount);

        // We force the node count to be this max node count if we are within a factor of 2.  
        // This ensures that we don't have an issue where growing algorithms overshoot the amount
        // of memory available and fail.   Note we do this on 64 bit too 
        if (estimatedObjectCount >= m_maxNodeCount / 2)
        {
            m_log.WriteLine("Limiting object count to {0:n0}", m_maxNodeCount);
            estimatedObjectCount = m_maxNodeCount + 2;
        }

        // Allocate a memory graph if we have not already.  
        if (m_gcHeapDump.MemoryGraph == null)
        {
            m_gcHeapDump.MemoryGraph = new MemoryGraph(estimatedObjectCount);
        }

        m_gcHeapDump.MemoryGraph.Is64Bit = EnvironmentUtilities.Is64BitProcess;

        ulong total = 0;
        m_log.WriteLine("DumpDotNetHeapDataWorker: Heap Size of dumper {0:n0} MB", GC.GetTotalMemory(false) / 1000000.0);

        int segmentCount = allSegments.Count();
        m_log.WriteLine("A total of {0} segments.", segmentCount);
        // Get the GC Segments to dump
        var gcHeapDumpSegments = new List<GCHeapDumpSegment>(segmentCount);
        foreach (var seg in allSegments)
        {
            var gcHeapDumpSegment = new GCHeapDumpSegment
            {
                Start = seg.Start,
                End = seg.End
            };

            // ClrMD returns UOH segments with seg.Generation2.Start == seg.Start and seg.Generation2.End == seg.End
            // To make it easy to determine the real generation of the object, augmenting the object with Gen3End and
            // Gen4End as follows such that DotNetHeapInfo.GenerationFor works.
            if (seg.Kind == GCSegmentKind.Pinned)
            {
                gcHeapDumpSegment.Gen0End = seg.End;
                gcHeapDumpSegment.Gen1End = seg.End;
                gcHeapDumpSegment.Gen2End = seg.End;
                gcHeapDumpSegment.Gen3End = seg.End;
                gcHeapDumpSegment.Gen4End = seg.End;
            }
            else if (seg.Kind == GCSegmentKind.Large)
            {
                gcHeapDumpSegment.Gen0End = seg.End;
                gcHeapDumpSegment.Gen1End = seg.End;
                gcHeapDumpSegment.Gen2End = seg.End;
                gcHeapDumpSegment.Gen3End = seg.End;
                gcHeapDumpSegment.Gen4End = seg.Start;
            }
            else
            {
                gcHeapDumpSegment.Gen0End = seg.Generation0.End;
                gcHeapDumpSegment.Gen1End = seg.Generation1.End;
                gcHeapDumpSegment.Gen2End = seg.Generation2.End;
                gcHeapDumpSegment.Gen3End = seg.Start;
                gcHeapDumpSegment.Gen4End = seg.Start;
            }

            gcHeapDumpSegments.Add(gcHeapDumpSegment);

            total += seg.Length;
            m_log.WriteLine("Segment: Start {0,16:x} Length: {1,16:x} {2,11:n3}M Kind:{3}", seg.Start, seg.Length, seg.Length / 1000000.0, seg.Kind);
        }

        m_log.WriteLine("Segment: Total {0,16} Length: {1,16:x} {2,11:n3}M", "", total, total / 1000000.0);

        m_gcHeapDump.InteropInfo = new InteropInfo();
        var dotNetRoot = DumpRoots(dataTarget, runtimes);

        m_log.WriteLine("{0,5:f1}s: Starting GC Graph Traversal.  This can take a while...", m_sw.Elapsed.TotalSeconds);
        double heapTravseralStartSec = m_sw.Elapsed.TotalSeconds;

        // If we are want to dump the whole heap, do it now, this is much more efficient.  
        long startSize = m_gcHeapDump.MemoryGraph.TotalSize;
        DumpAllSegments(dataTarget, runtimes);
        Debug.Assert(m_gcHeapDump.MemoryGraph.TotalSize - startSize < (long)totalGCSize);

        m_log.Write("{0,5:f1}s: Dump RCW/CCW information", m_sw.Elapsed.TotalSeconds);

        try
        {
            DumpCCWRCW(dataTarget);
        }
        catch (Exception e)
        {
            m_log.Write("Error: dumping CCW/RCW information\r\n{0}", e);
            m_gcHeapDump.InteropInfo = new InteropInfo();       // Clear the info
        }

        m_log.WriteLine("{0,5:f1}s: Done collecting data.", m_sw.Elapsed.TotalSeconds);

        var dotNetInfo = m_gcHeapDump.DotNetHeapInfo = new DotNetHeapInfo();

        // Write out the dump (TODO we should do this incrementally).    
        dotNetInfo.SizeOfAllSegments = (long)totalGCSize;
        dotNetInfo.Segments = gcHeapDumpSegments;

        m_gcHeapDump.MemoryGraph.RootIndex = dotNetRoot.Build();

        m_log.WriteLine("Number of bad objects during trace {0:n0}", BadObjectCount);
        m_log.WriteLine("{0,5:f1}s: Finished heap dump {1}", m_sw.Elapsed.TotalSeconds, DateTime.Now);
        return;
    }

    private readonly object _sync = new object();
    private MemoryNodeBuilder DumpRoots(DataTarget dataTarget, ClrRuntime[] runtimes)
    {
        int numRoots = 0;
        var dotNetRoot = new MemoryNodeBuilder(m_gcHeapDump.MemoryGraph, GCHeapDumpNames.Bracket(GCHeapDumpNames.DotNetRootsTitle));
        try
        {
            m_log.WriteLine("{0,5:f1}s: Scanning Static Variables", m_sw.Elapsed.TotalSeconds);

            foreach (ClrModule module in runtimes.SelectMany(r => r.EnumerateModules()))
            {
                ClrRuntime runtime = module.AppDomain.Runtime;

                foreach (var item in module.EnumerateTypeDefToMethodTableMap())
                {
                    ClrType type = runtime.GetTypeByMethodTable(item.MethodTable);
                    if (type is null)
                        continue;

                    foreach (ClrStaticField field in type.StaticFields.Where(sf => sf.IsObjectReference))
                    {
                        foreach (ClrAppDomain domain in runtime.AppDomains)
                        {
                            ClrObject obj = field.ReadObject(domain);

                            // Only report objects if they contain pointers (and therefore are interesting roots) or are large in size.
                            if (obj.IsValid && (obj.Type.ContainsPointers || obj.Size > 0x1000))
                            {
                                string name = $"static var {field.ContainingType?.Name}.{field.Name}";
                                ComCallableWrapper ccwInfo = obj.HasComCallableWrapper ? obj.GetComCallableWrapper() : null;

                                // We will use -1 to mean "static variable".
                                WriteRoot(dataTarget.DataReader, dotNetRoot, obj, (ClrRootKind)(-1), false, ccwInfo, name, ref numRoots);
                            }
                        }
                    }
                }
            }



            m_log.WriteLine("{0,5:f1}s: Scanning Actual GC roots", m_sw.Elapsed.TotalSeconds);
            var rootsStartTimeMSec = m_sw.Elapsed.TotalMilliseconds;
            foreach (ClrRoot root in runtimes.SelectMany(r => r.Heap.EnumerateRoots()))
            {
                if (!root.Object.IsValid)
                    continue;

                ClrObject obj = root.Object;
                ClrRootKind kind = root.RootKind;
                bool pinned = root.IsPinned;
                ComCallableWrapper ccwInfo = obj.HasComCallableWrapper ? obj.GetComCallableWrapper() : null;

                // NOTE: If changing these names, need to document as a breaking change in release notes.
                string name;
                switch (kind)
                {
                    case ClrRootKind.Stack:
                        name = GCHeapDumpNames.LocalVarsRootTitle;
                        break;

                    case ClrRootKind.RefCountedHandle:
                        name = GCHeapDumpNames.COMWinRTRootTitle;
                        break;

                    default:
                        name = GetRootTitle(kind);
                        break;
                };

                WriteRoot(dataTarget.DataReader, dotNetRoot, obj, kind, pinned, ccwInfo, name, ref numRoots);
            }

            var rootDuration = m_sw.Elapsed.TotalMilliseconds - rootsStartTimeMSec;
            m_log.WriteLine("Scanning UNNAMED GC roots took {0:n1} msec", rootDuration);
        }
        catch (Exception e) when (!(e is OutOfMemoryException))
        {
            m_log.WriteLine("[ERROR while processing roots: {0}", e.Message);
            m_log.WriteLine("Continuing without complete root information");
        }
        m_log.Flush();

        return dotNetRoot;
    }

    private static string GetRootTitle(ClrRootKind rootKind)
    {
        switch (rootKind)
        {
            case ClrRootKind.FinalizerQueue:
                return GCHeapDumpNames.FinalizerQueueRootTitle;
            case ClrRootKind.StrongHandle:
                return GCHeapDumpNames.StrongHandleRootTitle;
            case ClrRootKind.PinnedHandle:
                return GCHeapDumpNames.PinnedHandleRootTitle;
            case ClrRootKind.Stack:
                return GCHeapDumpNames.StackRootTitle;
            case ClrRootKind.RefCountedHandle:
                return GCHeapDumpNames.RefCountedHandleRootTitle;
            case ClrRootKind.AsyncPinnedHandle:
                return GCHeapDumpNames.AsyncPinnedHandleRootTitle;
            case ClrRootKind.SizedRefHandle:
                return GCHeapDumpNames.SizedRefHandleRootTitle;
            case ClrRootKind.None:
                return "None";
            default:
                throw new ArgumentOutOfRangeException("rootKind");
        };
    }

    private void WriteRoot(IDataReader reader, MemoryNodeBuilder dotNetRoot, ClrObject obj, ClrRootKind kind, bool pinned, ComCallableWrapper ccwInfo, string name, ref int numRoots)
    {
        // If there is a named root already then we assume that that root is the interesting one and we drop this one.  
        if (m_gcHeapDump.MemoryGraph.IsInGraph(obj))
            return;

        numRoots++;
        if (numRoots % 1024 == 0)
            m_log.WriteLine("{0,5:f1}s: Scanned {1} roots.", m_sw.Elapsed.TotalSeconds, numRoots);

        MemoryNodeBuilder nodeToAddRootTo = dotNetRoot;

        if (ccwInfo != null)
        {
            ulong comPtr = ccwInfo.IUnknown != 0 ? ccwInfo.IUnknown : ccwInfo.Interfaces.FirstOrDefault().InterfacePointer;

            // Create a CCW node that represents the COM object that has one child that points at the managed object.  
            var ccwNode = m_gcHeapDump.MemoryGraph.GetNodeIndex(ccwInfo.Handle);

            string typeName = $"[CCW for {obj.Type?.Name ?? "unknown"} RefCnt: {ccwInfo.RefCount:n0}]";
            var ccwTypeIndex = GetTypeIndexForName(typeName, null, 200);

            NodeIndex childNode = m_gcHeapDump.MemoryGraph.GetNodeIndex(obj);

            DumpCCW(reader, childNode, obj, ccwInfo);

            GrowableArray<NodeIndex> ccwChildren = new GrowableArray<NodeIndex>();
            ccwChildren.Add(childNode);

            if (comPtr != 0)
                m_gcHeapDump.MemoryGraph.SetNode(ccwNode, ccwTypeIndex, 200, ccwChildren);

            nodeToAddRootTo = nodeToAddRootTo.FindOrCreateChild(GCHeapDumpNames.Bracket(GCHeapDumpNames.COMWinRTRootTitle));
            nodeToAddRootTo.AddChild(ccwNode);
        }
        else
        {
            if (kind == (ClrRootKind)(-1))
                nodeToAddRootTo = nodeToAddRootTo.FindOrCreateChild(GCHeapDumpNames.Bracket(GCHeapDumpNames.StaticVarsRootTitle));

            // Add pinned local vars to their own node
            if (pinned && kind == ClrRootKind.Stack)
                nodeToAddRootTo = nodeToAddRootTo.FindOrCreateChild(GCHeapDumpNames.Bracket(GCHeapDumpNames.PinnedLocalVarsRootTitle));
            else
                nodeToAddRootTo = nodeToAddRootTo.FindOrCreateChild(GCHeapDumpNames.Bracket(name));

            NodeIndex child = m_gcHeapDump.MemoryGraph.GetNodeIndex(obj);
            nodeToAddRootTo.AddChild(child);
        }
    }

    /// <summary>
    /// Finalizes the data in m_gcHeapDump so it can be consumed or serialized.
    /// </summary>
    private void FinalizeDump(bool logLiveStats)
    {
        if (!m_gotDotNetData)
        {
            throw new HeapDumpException("Could not dump a .NET heap.  See log file for details", HR.NoHeapFound);
        }

        // Allow reading.  
        m_gcHeapDump.MemoryGraph.AllowReading();

        var maxDumpCount = MaxDumpCountK * 1000;
        if (maxDumpCount != 0 && maxDumpCount < m_gcHeapDump.MemoryGraph.NodeCount)
        {
            m_log.WriteLine("Object count {0}K > MaxDumpCount = {1}K, sampling", m_gcHeapDump.MemoryGraph.NodeCount / 1000, MaxDumpCountK);

            m_log.WriteLine("{0,5:f1}s:   Started Sampling.", m_sw.Elapsed.TotalSeconds);
            var graphSampler = new GraphSampler(m_gcHeapDump.MemoryGraph, maxDumpCount, m_log);
            var sampledGraph = graphSampler.GetSampledGraph();
            m_log.WriteLine("{0,5:f1}s:   Done Sampling.", m_sw.Elapsed.TotalSeconds);

            m_gcHeapDump.CountMultipliersByType = graphSampler.CountScalingByType;
            m_gcHeapDump.AverageCountMultiplier = (float)((double)m_gcHeapDump.MemoryGraph.NodeCount / sampledGraph.NodeCount);
            m_gcHeapDump.AverageSizeMultiplier = (float)((double)m_gcHeapDump.MemoryGraph.TotalSize / sampledGraph.TotalSize);
            m_log.WriteLine("Average Count Multiplier: {0,6:f2}", m_gcHeapDump.AverageCountMultiplier);
            m_log.WriteLine("Average Size Multiplier:  {0,6:f2}", m_gcHeapDump.AverageSizeMultiplier);

            m_gcHeapDump.MemoryGraph = sampledGraph;
            m_log.WriteLine("After sampling Object Count {0}K    Total GC Heap Size {1:f1} MB ",
                m_gcHeapDump.MemoryGraph.NodeCount, m_gcHeapDump.MemoryGraph.TotalSize / 1000000.0);
        }
        else
        {
            m_log.WriteLine("Object count {0}K less than {1}K, Dumped all objects.", m_gcHeapDump.MemoryGraph.NodeCount / 1000, MaxDumpCountK);
        }

        m_log.WriteLine("Dump Created from a .DMP file, no live statistics");


        // This code always matches the bitness of the process being dumped.  
        Debug.Assert(EnvironmentUtilities.Is64BitProcess == m_gcHeapDump.MemoryGraph.Is64Bit);
        m_log.WriteLine("The process being dumped is {0} Bit", m_gcHeapDump.MemoryGraph.Is64Bit ? 64 : 32);

        m_log.WriteLine("Actual number of objects dumped = {0:n0}", m_gcHeapDump.MemoryGraph.NodeCount);
        m_log.WriteLine("Actual number of types = {0:n0}", (int)m_gcHeapDump.MemoryGraph.NodeTypeIndexLimit);
        m_log.WriteLine("Size of dumped objects {0:n1} MB", m_gcHeapDump.MemoryGraph.TotalSize / 1000000.0);

        // Attach a copy of the log to the dump so consumers can use it without persisting it.
        m_log.Flush();
        m_gcHeapDump.CollectionLog = m_copyOfLog.ToString();
    }

    private int DumpRCW(IDataReader reader, NodeIndex node, Address addr, RuntimeCallableWrapper rcw)
    {
        try
        {
            InteropInfo.RCWInfo infoRCW = new InteropInfo.RCWInfo();
            infoRCW.node = node;
            infoRCW.refCount = rcw.RefCount;
            infoRCW.addrIUnknown = rcw.IUnknown;
            infoRCW.addrJupiter = rcw.WinRTObject;
            infoRCW.addrVTable = rcw.VTablePointer;
            infoRCW.firstComInf = m_gcHeapDump.InteropInfo.currentInterfaceCount;
            int countInterfaces = DumpInterfaces(reader, rcw.Interfaces, true);
            infoRCW.countComInf = countInterfaces;
            m_gcHeapDump.InteropInfo.AddRCW(infoRCW);
        }
        catch (System.NullReferenceException)
        {
            return 0;
        }

        return 1;
    }

    private void DumpCCW(IDataReader reader, NodeIndex node, Address addr, ComCallableWrapper ccw)
    {
        InteropInfo.CCWInfo infoCCW = new InteropInfo.CCWInfo();
        infoCCW.node = node;
        infoCCW.refCount = ccw.RefCount;
        infoCCW.addrIUnknown = ccw.IUnknown;
        infoCCW.addrHandle = ccw.Handle;
        infoCCW.firstComInf = m_gcHeapDump.InteropInfo.currentInterfaceCount;
        int countInterfaces = DumpInterfaces(reader, ccw.Interfaces, false);
        infoCCW.countComInf = countInterfaces;
        m_gcHeapDump.InteropInfo.AddCCW(infoCCW);
    }

    private int DumpInterfaces(IDataReader reader, IList<ComInterfaceData> infs, bool fRCW)
    {
        int countInterfaces = 0;

        if (infs != null)
        {
            foreach (ComInterfaceData inf in infs)
            {
                InteropInfo.ComInterfaceInfo infoComInterface = new InteropInfo.ComInterfaceInfo();
                infoComInterface.fRCW = fRCW;

                if (fRCW)
                {
                    infoComInterface.owner = m_gcHeapDump.InteropInfo.currentRCWCount;
                }
                else
                {
                    infoComInterface.owner = m_gcHeapDump.InteropInfo.currentCCWCount;
                }

                ClrType t = inf.Type;

                NodeTypeIndex ti = (NodeTypeIndex)(-1);

                if (t != null)
                {
                    ti = GetTypeIndexForClrType(t, 0);
                }

                infoComInterface.typeID = ti;

                ulong vftable = reader.ReadPointer(inf.InterfacePointer);
                ulong ffirst = reader.ReadPointer(vftable);

                infoComInterface.addrFirstVTable = vftable;
                infoComInterface.addrFirstFunc = ffirst;

                m_gcHeapDump.InteropInfo.AddComInterface(infoComInterface);

                countInterfaces++;
            }
        }

        return countInterfaces;
    }

    /// <summary>
    /// Gather information about CCW/RCW, write to m_gcHeapDump.InteropInfo.
    /// </summary>
    private void DumpCCWRCW(DataTarget dataTarget)
    {
        // We need module information to decode virtual function table pointers, and virtual function pointers.
        if (m_gcHeapDump.InteropInfo.InteropInfoExists())
        {
            foreach (ModuleInfo module in dataTarget.EnumerateModules())
            {
                InteropInfo.InteropModuleInfo infoModule = new InteropInfo.InteropModuleInfo();
                infoModule.baseAddress = module.ImageBase;
                infoModule.fileSize = (uint)module.IndexFileSize;
                infoModule.timeStamp = (uint)module.IndexTimeStamp;
                infoModule.fileName = module.FileName;
                m_gcHeapDump.InteropInfo.AddModule(infoModule);
            }
        }
    }

    /// <summary>
    /// DumpAllSegments dumps all the data in the GC heap in bulk (in order).  This means that both live and dead objects
    /// are collected (since we can't tell the difference at this point.  This is much more efficient if you want 
    /// to dump the whole heap.  
    /// </summary>
    private void DumpAllSegments(DataTarget dataTarget, ClrRuntime[] runtimes)
    {
        var segments = runtimes.SelectMany(r => r.Heap.Segments).OrderBy(seg => seg.Start).ToArray();

        m_log.WriteLine("Dumping {0} GC segments in the heap in bulk.", segments.Length);
        var segmentCount = 0;
        foreach (ClrSegment segment in segments)
        {
            var start = segment.Start;
            var end = segment.End;
            m_log.WriteLine("[{0,5:f1}s: Dumping segment {1} of {2} start: {3:x} len: {4:f2}M]", m_sw.Elapsed.TotalSeconds, segmentCount, segments.Length, start, (end - start) / 1000000.0);

            ulong nextStatusUpdateObj = 0;

            foreach (ClrObject obj in segment.EnumerateObjects())
            {
                if (obj.Type is null)
                    continue;

                m_children.Clear();

                foreach (ulong childObj in obj.EnumerateReferenceAddresses(carefully: true, considerDependantHandles: true))
                    m_children.Add(m_gcHeapDump.MemoryGraph.GetNodeIndex(childObj));

                var objNodeIdx = m_gcHeapDump.MemoryGraph.GetNodeIndex(obj);
                ulong objSize = obj.Size;
                int objSizeAsInt = objSize <= int.MaxValue ? (int)objSize : int.MaxValue;


                var memoryGraphTypeIdx = GetTypeIndexForClrType(obj.Type, objSizeAsInt);

                RuntimeCallableWrapper rcwData = obj.HasRuntimeCallableWrapper ? obj.GetRuntimeCallableWrapper() : null;
                if (rcwData != null)
                {
                    // Add the COM object this RCW points at as a child of this node.  
                    m_children.Add(m_gcHeapDump.MemoryGraph.GetNodeIndex(rcwData.IUnknown));

                    var fullTypeName = obj.Type.Name;
                    string moduleName = obj.Type.Module?.Name;
                    if (moduleName != null)
                        fullTypeName = Path.GetFileNameWithoutExtension(moduleName) + "!" + fullTypeName;

                    var typeName = $"[{GCHeapDumpNames.RCWPrefix} {fullTypeName} RefCnt: {rcwData.RefCount:n0}]";

                    // We add 1000 to account for the overhead of the RCW that is NOT on the GC heap.
                    if (objSizeAsInt < int.MaxValue - 1000)
                        objSizeAsInt += 1000;

                    memoryGraphTypeIdx = GetTypeIndexForName(typeName, null, objSizeAsInt);

                    DumpRCW(dataTarget.DataReader, objNodeIdx, obj, rcwData);
                }

                ComCallableWrapper ccwData = obj.HasComCallableWrapper ? obj.GetComCallableWrapper() : null;
                if (ccwData != null)
                    DumpCCW(dataTarget.DataReader, objNodeIdx, obj, ccwData);

                if (obj > nextStatusUpdateObj)
                {
                    m_log.WriteLine("{0,5:f1}s: Dumped {1:n0} objects, max_dump_limit {2:n0} Dumper heap Size {3:n0}MB",
                        m_sw.Elapsed.TotalSeconds, m_gcHeapDump.MemoryGraph.NodeCount, m_maxNodeCount, GC.GetTotalMemory(false) / 1000000.0);
                    nextStatusUpdateObj = obj + 1000000;        // log a message every 1 Meg 
                }

                if (m_gcHeapDump.MemoryGraph.NodeCount >= m_maxNodeCount ||
                    m_gcHeapDump.MemoryGraph.DistinctRefCount + m_children.Count > m_maxNodeCount)
                {
                    m_log.WriteLine("[WARNING, exceeded the maximum number of node allowed {0}]", m_maxNodeCount);
                    m_log.WriteLine("{0,5:f1}s: Truncating heap dump.", m_sw.Elapsed.TotalSeconds);
                    return;
                }

                m_gcHeapDump.MemoryGraph.SetNode(objNodeIdx, memoryGraphTypeIdx, objSizeAsInt, m_children);
            }
            segmentCount++;
        }

        m_log.WriteLine("{0,5:f1}s: Done Dumping all the segments.", m_sw.Elapsed.TotalSeconds);
    }

    /// <summary>
    /// Given a type, find the graph's type index for it.  If this is the first
    /// time we have seen the type we generate a new type for it and return that
    /// We do intern types (same type will return the same type index). 
    /// </summary>
    private NodeTypeIndex GetTypeIndexForClrType(ClrType type, int objSize)
    {
        int idx;
        if (!m_typeTable.TryGetValue(type, out idx))
        {
            idx = m_typeTable.Count;
            m_typeTable[type] = idx;
        }

        if (m_typeIdxToGraphIdx.Count <= idx)
        {
            m_typeIdxToGraphIdx.Count = idx + (m_typeIdxToGraphIdx.Count / 2 + 32);
        }

        // We add 1 so that 0 is an illegal value (to represent 'not present')
        var val = m_typeIdxToGraphIdx[idx] - 1;
        if (val >= 0)
        {
            return (NodeTypeIndex)val;
        }

        // We give more complex names to arrays and strings that are large
        NodeTypeIndex ret;
        var name = type.Name;
        if (type.IsString || type.IsArray || name == "Free")
        {
            var typeName = type.Name;
            var sizeStr = "";
            if (objSize > 1000)
            {
                string size;
                if (objSize < 10000)
                {
                    size = "1K";
                }
                else if (objSize < 100000)
                {
                    size = "10K";
                }
                else if (objSize < 1000000)
                {
                    size = "100K";
                }
                else if (objSize < 10000000)
                {
                    size = "1M";
                }
                else if (objSize < 100000000)
                {
                    size = "10M";
                }
                else
                {
                    size = "100M";
                }

                sizeStr = "Bytes > " + size;
            }

            if (type.IsArray)
            {
                var ptrs = "NoPtrs";
                if (type.ContainsPointers)
                {
                    ptrs = "Ptrs";
                }

                var sep = "";
                if (sizeStr.Length > 0)
                {
                    sep = ",";
                }

                typeName = typeName + " (" + sizeStr + sep + ptrs + ",ElemSize=" + type.ComponentSize.ToString() + ")";
            }
            else if (sizeStr.Length > 0)
            {
                typeName = typeName + " (" + sizeStr + ")";
            }

            ret = GetTypeIndexForName(typeName, type.Module?.Name, 0);
        }
        else
        {
            ret = GetTypeIndexForName(name ?? "<Unnamed " + type.MetadataToken.ToString("x8") + ">", type.Module?.Name, 0);
            m_typeIdxToGraphIdx[idx] = (int)ret + 1;
        }
        return ret;
    }

    private NodeTypeIndex GetTypeIndexForName(string typeName, string moduleName, int defaultSize)
    {
        NodeTypeIndex ret;
        if (!m_graphTypeIdxForArrayType.TryGetValue(typeName, out ret))
        {
            ret = m_gcHeapDump.MemoryGraph.CreateType(typeName, moduleName, defaultSize);
            m_graphTypeIdxForArrayType[typeName] = ret;
        }
        return ret;
    }

    private TextWriter m_origLog;           // What was passed into the constructor.
    private TextWriter m_log;               // Where we send messages
    private StringWriter m_copyOfLog;       // We keep a copy of all logged messages here to append to output file. 
    private Stopwatch m_sw;                 // We keep track of how long it takes.  

    private GCHeapDump m_gcHeapDump;        // The image of what we are putting in the file
    private int m_maxNodeCount;             // The maximum node count (to keep from getting out of memory exceptions)

    private bool m_gotDotNetData;           // Did we find a .NET heap?

    private GrowableArray<NodeIndex> m_children;
    private Dictionary<ClrType, int> m_typeTable = new Dictionary<ClrType, int>();
    private GrowableArray<int> m_typeIdxToGraphIdx;

    private Dictionary<string, NodeTypeIndex> m_graphTypeIdxForArrayType;
}




