package sample;

/**
 * Ordinary application. Its bytecode must remain byte-identical after
 * integration: it keeps calling the same public static Core roots
 * (scramble, narrow, blend - all three native exports), which are substituted
 * by native-backed facades. It parses argv, loops, does console IO and calls
 * System.exit - behavior the integer frontend does not lower and that stays in
 * ordinary application bytecode.
 *
 * Output uses explicit "\n" (not println) so stdout is exactly "<value>\n"
 * regardless of the platform line separator, which the application-contract
 * compares exactly.
 */
public final class App {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("usage: app <seed> <rounds>");
            System.exit(2);
        }
        int seed = Integer.parseInt(args[0]);
        int rounds = Integer.parseInt(args[1]);
        long total = 0L;
        for (int i = 0; i < rounds; i++) {
            int s = Core.scramble(seed + i, i + 1);
            int n = Core.narrow((long) s, i);
            total = Core.blend(total, (long) n);
        }
        System.out.print(Long.toString(total) + "\n");
    }
}
