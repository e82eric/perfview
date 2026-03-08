using Graphs;
using System;
using System.Diagnostics;

namespace Graphs
{
    internal sealed class PriorityQueue
    {
        public PriorityQueue(int initialSize = 32)
        {
            _heap = new DataItem[initialSize];
        }

        public int Count => _count;

        public void Enqueue(NodeIndex item, float priority)
        {
            int index = _count;
            if (index >= _heap.Length)
            {
                var newArray = new DataItem[_heap.Length * 3 / 2 + 8];
                Array.Copy(_heap, newArray, _heap.Length);
                _heap = newArray;
            }

            _heap[index].Value = item;
            _heap[index].Priority = priority;
            _count = index + 1;

            while (true)
            {
                int parent = index / 2;
                if (_heap[parent].Priority >= _heap[index].Priority)
                {
                    break;
                }

                (_heap[index], _heap[parent]) = (_heap[parent], _heap[index]);
                if (parent == 0)
                {
                    break;
                }

                index = parent;
            }
        }

        public NodeIndex Dequeue(out float priority)
        {
            Debug.Assert(_count > 0);

            NodeIndex value = _heap[0].Value;
            priority = _heap[0].Priority;
            _count--;
            _heap[0] = _heap[_count];

            int index = 0;
            while (true)
            {
                int childIndex = index * 2;
                int largestIndex = index;

                if (childIndex < Count && _heap[childIndex].Priority > _heap[largestIndex].Priority)
                {
                    largestIndex = childIndex;
                }

                childIndex++;
                if (childIndex < Count && _heap[childIndex].Priority > _heap[largestIndex].Priority)
                {
                    largestIndex = childIndex;
                }

                if (largestIndex == index)
                {
                    break;
                }

                (_heap[index], _heap[largestIndex]) = (_heap[largestIndex], _heap[index]);
                index = largestIndex;
            }

            return value;
        }

        private struct DataItem
        {
            public float Priority;
            public NodeIndex Value;
        }

        private DataItem[] _heap;
        private int _count;
    }
}
