using Azure.Core;
using Azure.Identity;
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Microsoft.Diagnostics.CompactTypeGraph;

public sealed class SingleParentTypeSummary
{
    internal SingleParentTypeSummary(int id, string name, string fullName, string moduleName, bool isSynthetic)
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
    public long ExclusiveBytes { get; internal set; }
    public long ExclusiveCount { get; internal set; }
    public long InclusiveBytes { get; internal set; }
    public long InclusiveCount { get; internal set; }
}

public static class SingleParentTypeSummaryBuilder
{
    public static IReadOnlyList<SingleParentTypeSummary> BuildFromMemoryDump(string dumpPath, TextWriter log = null)
    {
        if (string.IsNullOrWhiteSpace(dumpPath))
        {
            throw new ArgumentException("A dump path is required.", nameof(dumpPath));
        }

        log ??= TextWriter.Null;
        using DataTarget dataTarget = OpenDump(dumpPath);
        ClrRuntime[] runtimes = CreateRuntimes(dataTarget, log);

        var summaries = new List<SingleParentTypeSummary>();
        var summaryIdsByKey = new Dictionary<TypeKey, int>();
        var objectInfos = new Dictionary<ulong, ObjectInfo>(capacity: 1_000_000);
        var queue = new Queue<ulong>();
        var syntheticParents = new Dictionary<int, int>();

        ScanObjects(runtimes, summaries, summaryIdsByKey, objectInfos);
        AssignRootedParents(runtimes, summaries, summaryIdsByKey, objectInfos, queue, syntheticParents, log);
        AssignOrphanParents(runtimes, objectInfos, queue);
        ComputeInclusiveTotals(summaries, objectInfos, syntheticParents);

        return summaries;
    }

    private static void ScanObjects(
        ClrRuntime[] runtimes,
        List<SingleParentTypeSummary> summaries,
        Dictionary<TypeKey, int> summaryIdsByKey,
        Dictionary<ulong, ObjectInfo> objectInfos)
    {
        foreach (ClrSegment segment in runtimes.SelectMany(runtime => runtime.Heap.Segments).OrderBy(segment => segment.Start))
        {
            foreach (ClrObject obj in segment.EnumerateObjects())
            {
                if (obj.Type is null)
                {
                    continue;
                }

                int summaryId = GetOrCreateTypeSummaryId(obj.Type, summaryIdsByKey, summaries);
                summaries[summaryId].ExclusiveBytes += checked((long)obj.Size);
                summaries[summaryId].ExclusiveCount++;
                objectInfos[obj.Address] = new ObjectInfo(obj.Address, checked((long)obj.Size), summaryId);
            }
        }
    }

    private static void AssignRootedParents(
        ClrRuntime[] runtimes,
        List<SingleParentTypeSummary> summaries,
        Dictionary<TypeKey, int> summaryIdsByKey,
        Dictionary<ulong, ObjectInfo> objectInfos,
        Queue<ulong> queue,
        Dictionary<int, int> syntheticParents,
        TextWriter log)
    {
        int dotNetRootsId = GetOrCreateSyntheticSummaryId(Bracket(RootNames.DotNetRootsTitle), summaryIdsByKey, summaries);

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

                            int staticVarsId = GetOrCreateSyntheticSummaryId(Bracket(RootNames.StaticVarsRootTitle), summaryIdsByKey, summaries);
                            int namedRootId = GetOrCreateSyntheticSummaryId(
                                Bracket($"{RootNames.StaticVarPrefix} {field.ContainingType?.Name}.{field.Name}"),
                                summaryIdsByKey,
                                summaries);

                            syntheticParents[staticVarsId] = dotNetRootsId;
                            syntheticParents[namedRootId] = staticVarsId;
                            TryAssignSyntheticParent(objectInfos, queue, obj.Address, namedRootId);
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

                int categoryId = GetOrCreateSyntheticSummaryId(Bracket(GetRootCategoryTitle(root.RootKind, root.IsPinned)), summaryIdsByKey, summaries);
                syntheticParents[categoryId] = dotNetRootsId;
                TryAssignSyntheticParent(objectInfos, queue, root.Object.Address, categoryId);
            }

            TraverseAssignedObjects(runtimes, objectInfos, queue);
        }
        catch (Exception ex) when (!(ex is OutOfMemoryException))
        {
            log.WriteLine("[ERROR while building single-parent traversal: {0}]", ex.Message);
            log.WriteLine("Continuing with partial root information.");
        }
    }

    private static void AssignOrphanParents(ClrRuntime[] runtimes, Dictionary<ulong, ObjectInfo> objectInfos, Queue<ulong> queue)
    {
        foreach (ObjectInfo objectInfo in objectInfos.Values)
        {
            if (objectInfo.IsAssigned)
            {
                continue;
            }

            objectInfo.IsAssigned = true;
            queue.Enqueue(objectInfo.Address);
            TraverseAssignedObjects(runtimes, objectInfos, queue);
        }
    }

    private static void TraverseAssignedObjects(ClrRuntime[] runtimes, Dictionary<ulong, ObjectInfo> objectInfos, Queue<ulong> queue)
    {
        while (queue.Count > 0)
        {
            ulong currentAddress = queue.Dequeue();
            ClrObject currentObject = GetObject(runtimes, currentAddress);
            if (!currentObject.IsValid)
            {
                continue;
            }

            foreach (ulong childAddress in currentObject.EnumerateReferenceAddresses(carefully: true, considerDependantHandles: true))
            {
                if (!objectInfos.TryGetValue(childAddress, out ObjectInfo childInfo) || childInfo.IsAssigned)
                {
                    continue;
                }

                childInfo.IsAssigned = true;
                childInfo.ParentObjectAddress = currentAddress;
                queue.Enqueue(childAddress);
            }
        }
    }

    private static void ComputeInclusiveTotals(
        List<SingleParentTypeSummary> summaries,
        Dictionary<ulong, ObjectInfo> objectInfos,
        Dictionary<int, int> syntheticParents)
    {
        foreach (ObjectInfo objectInfo in objectInfos.Values)
        {
            var seenSummaryIds = new HashSet<int>();
            AddInclusiveContribution(summaries, seenSummaryIds, objectInfo.TypeSummaryId, objectInfo.Size);

            ulong parentAddress = objectInfo.ParentObjectAddress;
            while (parentAddress != 0 && objectInfos.TryGetValue(parentAddress, out ObjectInfo parentInfo))
            {
                AddInclusiveContribution(summaries, seenSummaryIds, parentInfo.TypeSummaryId, objectInfo.Size);
                parentAddress = parentInfo.ParentObjectAddress;
            }

            int syntheticId = objectInfo.ParentSyntheticSummaryId;
            while (syntheticId >= 0)
            {
                AddInclusiveContribution(summaries, seenSummaryIds, syntheticId, objectInfo.Size);
                syntheticId = syntheticParents.TryGetValue(syntheticId, out int parentSyntheticId) ? parentSyntheticId : -1;
            }
        }
    }

    private static void AddInclusiveContribution(
        List<SingleParentTypeSummary> summaries,
        HashSet<int> seenSummaryIds,
        int summaryId,
        long objectSize)
    {
        if (!seenSummaryIds.Add(summaryId))
        {
            return;
        }

        summaries[summaryId].InclusiveBytes += objectSize;
        summaries[summaryId].InclusiveCount++;
    }

    private static void TryAssignSyntheticParent(
        Dictionary<ulong, ObjectInfo> objectInfos,
        Queue<ulong> queue,
        ulong objectAddress,
        int syntheticSummaryId)
    {
        if (!objectInfos.TryGetValue(objectAddress, out ObjectInfo objectInfo) || objectInfo.IsAssigned)
        {
            return;
        }

        objectInfo.IsAssigned = true;
        objectInfo.ParentSyntheticSummaryId = syntheticSummaryId;
        queue.Enqueue(objectAddress);
    }

    private static int GetOrCreateTypeSummaryId(
        ClrType type,
        Dictionary<TypeKey, int> summaryIdsByKey,
        List<SingleParentTypeSummary> summaries)
    {
        string typeName = type.Name ?? string.Empty;
        string moduleName = type.Module?.Name;
        string fullName = moduleName == null ? typeName : $"{moduleName}!{typeName}";
        var key = new TypeKey(fullName, typeName, moduleName, false);
        if (!summaryIdsByKey.TryGetValue(key, out int summaryId))
        {
            summaryId = summaries.Count;
            summaryIdsByKey.Add(key, summaryId);
            summaries.Add(new SingleParentTypeSummary(summaryId, key.Name, key.FullName, key.ModuleName, false));
        }

        return summaryId;
    }

    private static int GetOrCreateSyntheticSummaryId(
        string fullName,
        Dictionary<TypeKey, int> summaryIdsByKey,
        List<SingleParentTypeSummary> summaries)
    {
        var key = new TypeKey(fullName, fullName, null, true);
        if (!summaryIdsByKey.TryGetValue(key, out int summaryId))
        {
            summaryId = summaries.Count;
            summaryIdsByKey.Add(key, summaryId);
            summaries.Add(new SingleParentTypeSummary(summaryId, key.Name, key.FullName, key.ModuleName, true));
        }

        return summaryId;
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

    private static string GetRootCategoryTitle(ClrRootKind kind, bool pinned)
    {
        if (pinned && kind == ClrRootKind.Stack)
        {
            return RootNames.PinnedLocalVarsRootTitle;
        }

        return kind switch
        {
            ClrRootKind.Stack => RootNames.LocalVarsRootTitle,
            ClrRootKind.RefCountedHandle => RootNames.COMWinRTRootTitle,
            ClrRootKind.FinalizerQueue => RootNames.FinalizerQueueRootTitle,
            ClrRootKind.StrongHandle => RootNames.StrongHandleRootTitle,
            ClrRootKind.PinnedHandle => RootNames.PinnedHandleRootTitle,
            ClrRootKind.AsyncPinnedHandle => RootNames.AsyncPinnedHandleRootTitle,
            ClrRootKind.SizedRefHandle => RootNames.SizedRefHandleRootTitle,
            ClrRootKind.None => "None",
            _ => RootNames.OtherRootsTitle
        };
    }

    private static string Bracket(string value) => $"[{value}]";

    private sealed class ObjectInfo
    {
        public ObjectInfo(ulong address, long size, int typeSummaryId)
        {
            Address = address;
            Size = size;
            TypeSummaryId = typeSummaryId;
        }

        public ulong Address { get; }
        public long Size { get; }
        public int TypeSummaryId { get; }
        public bool IsAssigned { get; set; }
        public ulong ParentObjectAddress { get; set; }
        public int ParentSyntheticSummaryId { get; set; } = -1;
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
