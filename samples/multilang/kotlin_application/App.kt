package sample

// Ordinary Kotlin application compiled against the original core metadata. Its
// bytecode keeps calling the same binary identities sample.Core.scramble(II)I,
// sample.Core.narrow(JI)I and sample.Core.blend(JJ)J (all three native exports),
// which are substituted by native-backed facades. It parses argv, loops, does
// console IO and exits - behavior that stays in ordinary application bytecode
// and is not lowered. Compiles to class sample.AppKt (the integration main_class).
//
// Output uses explicit "\n" with print (not println) so stdout is exactly
// "<value>\n" regardless of the platform line separator.
fun main(args: Array<String>) {
    if (args.size != 2) {
        System.err.println("usage: app <seed> <rounds>")
        kotlin.system.exitProcess(2)
    }
    val seed = args[0].toInt()
    val rounds = args[1].toInt()
    var total = 0L
    var i = 0
    while (i < rounds) {
        val s = scramble(seed + i, i + 1)
        val n = narrow(s.toLong(), i)
        total = blend(total, n.toLong())
        i++
    }
    print(total.toString() + "\n")
}
