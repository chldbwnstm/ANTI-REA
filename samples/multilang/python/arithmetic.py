"""Owned pure-Python arbitrary-integer fixture; no native-width wrapping."""

BIAS = 193


def mix_part(value, salt):
    shifted = (value ^ salt) << (abs(salt) % 5)
    return shifted * (salt | 1) + BIAS


def integer_score(x: int, y: int) -> int:
    total = mix_part(x, y)
    divisor = abs(y) % 23 + 1
    for index in range(5):
        total = (total * 17 + index) ^ (x >> index)
        if total % 3 == 0:
            total += mix_part(y, index)
        else:
            total -= x // divisor
    return total + x % divisor - y // divisor
