package sample;

/** Synthetic integer algorithms, not authentication or cryptography. */
public final class Algorithms {
    private static int prepare(int x, int y) {
        int value = x * 137 + y;
        return value ^ (value >>> (y + 3));
    }

    public static int fold(int x, int shift) {
        int value = prepare(x, shift);
        for (int i = 0; i < 4; i++) {
            value = value * 131 + i;
            value ^= value >> (shift + i);
            if (value < shift) value = ~value;
            else value -= shift;
        }
        return value;
    }

    public static long wide(long x, long y) {
        long value = (x + y) * 0x100000001b3L;
        value ^= value >> (int)y;
        if (x < y) value = -value + x;
        else value ^= y << (int)x;
        return value;
    }

    public static int narrow(long x, int mode) {
        int value = (int)x;
        switch (mode & 3) {
            case 0: return (byte)value;
            case 1: return (short)value;
            case 2: return (char)value;
            default: return value >>> mode;
        }
    }
}
