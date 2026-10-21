"""Owned fixture with intentional native Python error cases."""


def exceptional_value(x, y):
    if x % 5 == 0:
        return x << y
    if x % 5 == 1:
        return x // y
    if x % 5 == 2:
        return x % y
    if x % 5 == 3:
        for item in range(0, 3, y):
            return item + x
        return x
    if y:
        assigned = x + y
    return assigned
