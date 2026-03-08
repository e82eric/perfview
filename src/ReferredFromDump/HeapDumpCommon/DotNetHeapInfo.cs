using System.Collections.Generic;
using Address = System.UInt64;
public sealed class DotNetHeapInfo
{
    public int CorruptedObject { get; internal set; }
    public long UndumpedSegementRegion { get; internal set; }
    public long SizeOfAllSegments { get; internal set; }
    public List<GCHeapDumpSegment> Segments { get; internal set; }
    public int GenerationFor(Address obj)
    {
        if (lastSegment == null || !(lastSegment.Start <= obj && obj < lastSegment.End))
        {
            if (Segments == null)
            {
                return -1;
            }
            lastSegment = null;
            foreach (GCHeapDumpSegment segment in Segments)
            {
                if (segment.Start <= obj && obj < segment.End)
                {
                    lastSegment = segment;
                    break;
                }
            }
            if (lastSegment == null)
            {
                return -1;
            }
        }
        if (obj < lastSegment.Gen4End) return 4;
        if (obj < lastSegment.Gen3End) return 3;
        if (obj < lastSegment.Gen2End) return 2;
        if (obj < lastSegment.Gen1End) return 1;
        if (obj < lastSegment.Gen0End) return 0;
        return -1;
    }
    private GCHeapDumpSegment lastSegment;
}
public sealed class GCHeapDumpSegment
{
    public Address Start { get; internal set; }
    public Address End { get; internal set; }
    public Address Gen0End { get; internal set; }
    public Address Gen1End { get; internal set; }
    public Address Gen2End { get; internal set; }
    public Address Gen3End { get; internal set; }
    public Address Gen4End { get; internal set; }
}
