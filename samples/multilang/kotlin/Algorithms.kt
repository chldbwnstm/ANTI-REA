@file:JvmName("KotlinAlgorithms")
package sample

// Actual Kotlin source: integer-only top-level static methods and an owned helper.
private fun prepare(x: Int, y: Int): Int {
    val v = x * 137 + y
    return v xor (v ushr (y + 3))
}

fun fold(x: Int, shift: Int): Int {
    var value = prepare(x, shift)
    var i = 0
    while (i < 4) {
        value = value * 131 + i
        value = value xor (value shr (shift + i))
        value = if (value < shift) value.inv() else value - shift
        i++
    }
    return value
}

fun wide(x: Long, y: Long): Long {
    var value = (x + y) * 0x100000001b3L
    value = value xor (value shr y.toInt())
    return if (x < y) -value + x else value xor (y shl x.toInt())
}

fun narrow(x: Long, mode: Int): Int {
    val value = x.toInt()
    return when (mode and 3) {
        0 -> value.toByte().toInt()
        1 -> value.toShort().toInt()
        2 -> value.toChar().code
        else -> value ushr mode
    }
}
