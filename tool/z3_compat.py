import sys

import z3


_CHUNK_DIGITS = 9
_CHUNK_BASE = 10 ** _CHUNK_DIGITS


def _int_to_decimal_unlimited(value):
    """
    Convert a Python int to decimal without rendering the complete integer
    through Python's guarded int-to-string conversion.
    """

    if isinstance(value, bool):
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

    if value == 0:
        return "0"

    negative = value < 0

    if negative:
        value = -value

    chunks = []

    while value:
        value, remainder = divmod(
            value,
            _CHUNK_BASE,
        )

        chunks.append(
            remainder
        )

    head = str(
        chunks.pop()
    )

    tail = "".join(
        "%09d" % chunk
        for chunk
        in reversed(chunks)
    )

    result = (
        head
        + tail
    )

    if negative:
        result = (
            "-"
            + result
        )

    return result


def install_z3_int_compat():
    """
    Work around legacy Z3Py integer rendering on Python runtimes with
    int_max_str_digits.

    Ordinary-size integers keep using Z3Py's original path. Only integers
    large enough to risk Python's decimal conversion guard use the
    chunked conversion.
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

    get_limit = getattr(
        sys,
        "get_int_max_str_digits",
        None,
    )

    if get_limit is None:
        return False

    limit = get_limit()

    if limit == 0:
        return False

    #
    # Feature-detect the actual legacy Z3Py problem.
    #
    # Four binary bits per configured decimal digit are guaranteed to
    # exceed the decimal digit limit by a comfortable margin.
    #
    probe = 1 << (
        limit * 4
    )

    try:
        current(
            probe
        )

    except ValueError as exc:
        if (
            "integer string conversion"
            not in str(exc)
        ):
            raise

    else:
        # Z3Py already knows how to handle large integers.
        return False

    original = current

    #
    # Three binary bits per decimal digit are always safely below the
    # decimal limit because 2**3 == 8 < 10.
    #
    # Therefore normal integers keep the original Z3Py fast path.
    #
    safe_bit_length = (
        limit * 3
    )

    def safe_to_int_str(value):
        if isinstance(
                value,
                bool):
            return original(
                value
            )

        if isinstance(
                value,
                int):

            if (
                value.bit_length()
                <= safe_bit_length
            ):
                return original(
                    value
                )

            return _int_to_decimal_unlimited(
                value
            )

        return original(
            value
        )

    safe_to_int_str._karonte_large_int_compat = True
    safe_to_int_str._karonte_original = original
    safe_to_int_str._karonte_safe_bit_length = (
        safe_bit_length
    )

    target._to_int_str = safe_to_int_str

    return True
