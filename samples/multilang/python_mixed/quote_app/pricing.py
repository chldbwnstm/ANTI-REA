"""Keep the presentation layer; virtualize the selected integer calculation."""

from .settings import CURRENCY, TITLE


def rounded_discount(subtotal: int, basis_points: int) -> int:
    return (subtotal * basis_points + 5000) // 10000


def quote_cents(unit_cents: int, quantity: int, discount_basis_points: int) -> int:
    subtotal = unit_cents * quantity
    return subtotal - rounded_discount(subtotal, discount_basis_points)


def render_quote(unit_cents, quantity, discount_basis_points=0):
    """Validate UI input and format the result without hiding public labels."""
    values = (unit_cents, quantity, discount_basis_points)
    if any(type(value) is not int for value in values):
        raise TypeError("Quote inputs must be ordinary integers")
    if unit_cents < 0 or quantity < 0 or not 0 <= discount_basis_points <= 10000:
        raise ValueError("Use nonnegative price/quantity and a discount of 0..10000 basis points")
    total = quote_cents(unit_cents, quantity, discount_basis_points)
    return f"{TITLE}: {quantity} items, total {CURRENCY} {total // 100}.{total % 100:02d}"
