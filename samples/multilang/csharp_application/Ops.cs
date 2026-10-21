namespace Sample;

// Synthetic integer routines used to exercise source-level native integration.
// These are not cryptography or access control; they are deterministic integer
// algorithms whose bodies the ANTI-REA C# IL->native backend can lower.
public static class Ops
{
    // SELECTED core: call-free signed 32-bit integer leaf.
    public static int Transform(int state, int key)
    {
        unchecked
        {
            int value = state;
            for (int i = 0; i < 4; ++i)
            {
                value = (value * 131) + key + i;
                value ^= value >> 7;
                if ((value & 1) != 0) value += key;
                else value -= i;
            }
            return value;
        }
    }

    // SELECTED core: call-free signed 64-bit leaf with different ABI widths.
    public static long Accumulate(long acc, long sample)
    {
        unchecked
        {
            long value = acc ^ (sample * 0x100000001b3L);
            value += (value << 13) | 1L;
            value ^= value >> 11;
            return value - sample;
        }
    }

    // SELECTED helper: unsigned 32-bit leaf, routed through the same interop
    // surface as the cores. "Helper" by role; still a closed call-free leaf.
    public static uint FoldHelper(uint lo, uint hi)
    {
        unchecked
        {
            uint value = (lo << 7) ^ (hi + 0x9183u);
            value ^= value >> 5;
            value *= 0x01000193u;
            return value + (lo ^ hi);
        }
    }

    // UNSELECTED caller: orchestrates the public API with arrays/loops the
    // integer frontend does not support. It stays fully managed and keeps
    // calling the SAME public surface, which now routes into the native core.
    public static long Pipeline(int seed, int rounds)
    {
        long total = 0;
        int state = seed;
        for (int i = 0; i < rounds; ++i)
        {
            state = Transform(state, i + 1);
            uint folded = FoldHelper((uint)state, (uint)(i * 2654435761u));
            total = Accumulate(total, (long)folded + state);
        }
        return total;
    }
}
