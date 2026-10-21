namespace Sample;

// Synthetic integer algorithms, not access control or cryptography.
public static class Algorithms
{
    public static ulong Mix(uint x, uint y)
    {
        unchecked
        {
            ulong value = ((ulong)x << 17) ^ ((ulong)y + 0x9183u);
            for (uint i = 0; i < 4; ++i)
            {
                value ^= value >> 13;
                value *= 0x100000001b3UL;
                if (((value ^ i) & 1) != 0) value += ((ulong)y << 7) + i;
                else value ^= ((ulong)x << 11) + 0x51edu;
            }
            return value + ((ulong)x ^ y);
        }
    }

    public static int Fold(int value, int shift)
    {
        unchecked
        {
            for (int i = 0; i < 3; ++i)
            {
                value = (value * 137) + i;
                value ^= value >> (shift + i);
                if (value < shift) value = ~value;
                else value -= shift;
            }
            return value;
        }
    }

    public static long Wide(long x, long y)
    {
        unchecked
        {
            long a = (x + y) * 0x100000001b3L;
            a ^= a >> (int)y;
            if (x < y) a = -a + x;
            else a ^= y << (int)x;
            return a;
        }
    }
}
