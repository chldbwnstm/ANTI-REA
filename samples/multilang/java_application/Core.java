package sample;

/**
 * Synthetic integer core: three pure scalar public static int/long roots plus
 * one private static helper pulled into the owned protected closure. This is
 * NOT cryptography or access control; it is a deterministic integer algorithm
 * whose bodies the ANTI-REA JVM bytecode frontend can lower to the protected
 * native core.
 *
 * After source integration a same-name Java facade replaces this class and
 * forwards scramble/blend/narrow to the packaged protected native core; this
 * original source and its private helper are build evidence, never deployed.
 */
public final class Core {
    // SELECTED helper: private static int leaf, pulled into the owned closure
    // (reachable from both scramble and narrow). Never exported, never deployed.
    private static int step(int v, int k) {
        v = v + k;
        v ^= (v << 3);
        return v;
    }

    // SELECTED root: public static signed 32-bit integer entry point (II)I.
    // The iteration count is masked to 0..7 (rounds & 7) so that FULL-WIDTH int32
    // scalar validation (root source-validate feeds arbitrary/boundary rounds,
    // incl. INT_MAX) performs finite, terminating work for every input. This is a
    // fixture-validation bound, NOT a defense enhancement, and it is applied
    // identically to the original and the lowered native. The application only
    // ever passes rounds in 1..4, for which (rounds & 7) == rounds, so observable
    // application behaviour is unchanged.
    public static int scramble(int seed, int rounds) {
        int v = seed;
        int limit = rounds & 7;
        for (int i = 1; i <= limit; i++) {
            v = step(v, i);
        }
        return v;
    }

    // SELECTED root: public static signed 64-bit leaf (JJ)J.
    public static long blend(long acc, long x) {
        return acc * 31L + x;
    }

    // SELECTED root: mixed-width leaf (JI)I exercising long->int truncation.
    public static int narrow(long x, int mode) {
        int v = (int) x;
        v = step(v, mode);
        return v;
    }
}
