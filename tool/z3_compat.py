import sys

import z3


_get_int_limit = getattr(
    sys,
    "get_int_max_str_digits",
    None,
)

if _get_int_limit is None:
    _INT_STRING_CHUNK_SIZE = None
else:
    _limit = _get_int_limit()

    _INT_STRING_CHUNK_SIZE = (
        _limit
        if _limit > 0
        else None
    )


_INT_STRING_CHUNK_BASE = (
    10 ** _INT_STRING_CHUNK_SIZE
    if _INT_STRING_CHUNK_SIZE
    else None
)


def _int_to_decimal_unlimited(value):
    """
    Convert an integer to decimal without exceeding Python's guarded
    int-to-string conversion limit.

    This follows the strategy used by modern Claripy: split very large
    integers into decimal chunks no larger than int_max_str_digits.
    """

    if isinstance(
            value,
            bool):
        return (
            "1"
            if value
            else "0"
        )

    if not isinstance(
            value,
            int):
        raise TypeError(
            "value must be an int"
        )

    if (
        _INT_STRING_CHUNK_SIZE is None
    ):
        return str(
            value
        )

    if value == 0:
        return "0"

    negative = value < 0

    if negative:
        value = -value

    chunks = []

    while value:
        value, remainder = divmod(
            value,
            _INT_STRING_CHUNK_BASE,
        )

        chunks.append(
            remainder
        )

    result = str(
        chunks.pop()
    )

    while chunks:
        result += str(
            chunks.pop()
        ).zfill(
            _INT_STRING_CHUNK_SIZE
        )

    if negative:
        result = (
            "-"
            + result
        )

    return result


def install_z3_int_compat():
    """
    Backport modern Claripy's large-integer Z3 compatibility behavior.

    Ordinary integers retain Z3Py's original conversion path. Only values
    large enough to risk Python's int_max_str_digits guard use the
    unlimited chunked conversion.
    """

    target = z3.z3

    current = getattr(
        target,
        "_to_int_str",
        None,
    )

    if current is None:
        return False

    if getattr(
            current,
            "_karonte_large_int_compat",
            False):
        return False

    if (
        _INT_STRING_CHUNK_SIZE
        is None
    ):
        return False

    original = current

    #
    # Feature detection:
    # only patch Z3Py if its own integer conversion still fails.
    #
    probe = (
        1
        << (
            _INT_STRING_CHUNK_SIZE
            * 4
        )
    )

    try:
        original(
            probe
        )

    except ValueError as exc:
        if (
            "integer string conversion"
            not in str(exc)
        ):
            raise

    else:
        return False

    #
    # 2**(3*n) has fewer than n decimal digits because 8**n < 10**n.
    # This gives ordinary integers a conservative fast path through the
    # original Z3Py implementation.
    #
    safe_bit_length = (
        _INT_STRING_CHUNK_SIZE
        * 3
    )

    def safe_to_int_str(value):
        if (
            isinstance(
                value,
                int,
            )
            and not isinstance(
                value,
                bool,
            )
        ):
            if (
                value.bit_length()
                > safe_bit_length
            ):
                return (
                    _int_to_decimal_unlimited(
                        value
                    )
                )

        return original(
            value
        )

    safe_to_int_str._karonte_large_int_compat = True
    safe_to_int_str._karonte_original = original
    safe_to_int_str._karonte_safe_bit_length = (
        safe_bit_length
    )

    target._to_int_str = (
        safe_to_int_str
    )

    return True
