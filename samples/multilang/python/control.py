"""Owned loop/short-circuit/comparison fixture, deliberately not a score mixer."""


def count_steps(value):
    value = abs(value) % 29
    count = 0
    while value:
        count += 1
        value //= 2
    else:
        count += 7
    return count


def control_value(x, y):
    result = x and (y or -11)
    for index in range(abs(x) % 12, -2, -1):
        if index == 4 and y < 0:
            break
        if index % 3 == 0:
            continue
        result += count_steps(index + y)
    else:
        result ^= 0x1F31
    remaining = abs(y) % 8
    while remaining:
        remaining -= 1
        if remaining == 2 and x < 0:
            break
        if remaining % 2:
            continue
        result += remaining
    else:
        result += 113
    return result if -100 < x <= y + 200 else ~result
