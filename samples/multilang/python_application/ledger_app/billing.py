"""Keep the presentation layer; virtualize the selected integer settlement math.

``net_settlement`` and its helper ``rounded_fee`` use only their integer
parameters and local values -- no module globals -- so the mixed-module backend
can protect them. The ordinary ``render_statement`` presentation function reads
public labels, validates command-line input and calls the selected function by
its original name; it stays unprotected.
"""

from .labels import CURRENCY, STATEMENT_LABEL


def rounded_fee(amount: int, rate_bps: int) -> int:
    return (amount * rate_bps + 5000) // 10000


def net_settlement(gross_cents: int, item_count: int, fee_bps: int) -> int:
    gross = gross_cents * item_count
    return gross - rounded_fee(gross, fee_bps)


def render_statement(gross_cents, item_count, fee_bps=0):
    """Validate ordinary CLI input and format the statement without hiding labels."""
    values = (gross_cents, item_count, fee_bps)
    if any(type(value) is not int for value in values):
        raise TypeError("Settlement inputs must be ordinary integers")
    if gross_cents < 0 or item_count < 0 or not 0 <= fee_bps <= 10000:
        raise ValueError("Use nonnegative amounts and a fee of 0..10000 basis points")
    net = net_settlement(gross_cents, item_count, fee_bps)
    return f"{STATEMENT_LABEL}: {item_count} items, net {CURRENCY} {net // 100}.{net % 100:02d}"
