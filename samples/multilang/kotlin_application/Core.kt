@file:JvmName("Core")
package sample

// Synthetic integer core: three top-level int/long functions plus one private
// helper. With @file:JvmName("Core") this compiles to class sample.Core exposing
// public static scramble(II)I, blend(JJ)J, narrow(JI)I and private static
// step(II)I - the same binary identities a Java core would expose, so a
// same-name Java facade can substitute them after integration. This is NOT
// cryptography or access control. @Metadata/reflection are NOT preserved.

// SELECTED helper: private static int leaf, pulled into the owned closure
// (reachable from both scramble and narrow). Never exported, never deployed.
private fun step(v0: Int, k: Int): Int {
    var v = v0 + k
    v = v xor (v shl 3)
    return v
}

// SELECTED root: public static signed 32-bit integer entry point (II)I.
// The iteration count is masked to 0..7 (rounds and 7) so that FULL-WIDTH int32
// scalar validation (root source-validate feeds arbitrary/boundary rounds, incl.
// INT_MAX) performs finite, terminating work for every input. This is a
// fixture-validation bound, NOT a defense enhancement, applied identically to the
// original and the lowered native. The application only ever passes rounds in
// 1..4, for which (rounds and 7) == rounds, so observable behaviour is unchanged.
fun scramble(seed: Int, rounds: Int): Int {
    var v = seed
    val limit = rounds and 7
    var i = 1
    while (i <= limit) {
        v = step(v, i)
        i++
    }
    return v
}

// SELECTED root: public static signed 64-bit leaf (JJ)J.
fun blend(acc: Long, x: Long): Long = acc * 31L + x

// SELECTED root: mixed-width leaf (JI)I exercising long->int truncation.
fun narrow(x: Long, mode: Int): Int {
    var v = x.toInt()
    v = step(v, mode)
    return v
}
