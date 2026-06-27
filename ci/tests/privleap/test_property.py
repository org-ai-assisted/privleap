#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Hypothesis property-based tests for privleap's pure parser helpers.

Complements the autopkgtest (which drives the whole daemon) and the Atheris
harness (fuzz/fuzz_privleap.py, which fuzzes the framed parser) by generating
arbitrary inputs and asserting invariants that must hold for ALL inputs to the
small, security-relevant pure functions in privleap.privleap:

  - the argument-count codec is a faithful round-trip over its whole domain
    (0..63) and rejects everything outside it, never with a surprise exception;
  - validate_id never raises on any input and is a pure predicate; and a string
    it accepts as a SIGNAL_NAME really is within the documented charset and
    length bound (so a name that passes validation cannot smuggle a space or a
    control byte into the protocol).

Run locally:
    PYTHONPATH=usr/lib/python3/dist-packages \
      python3 -m pytest --import-mode=importlib \
        ci/tests/privleap/test_property.py
"""

import unittest

from hypothesis import given, settings, strategies as st

from privleap.privleap import PrivleapCommon, PrivleapValidateType


class TestArgCountCodec(unittest.TestCase):
    """Properties of int_to_msg_arg_count / msg_arg_count_to_int."""

    @given(st.integers(min_value=0, max_value=63))
    def test_roundtrip(self, n: int) -> None:
        """Every count in range encodes to a single char and decodes back."""
        chr_val = PrivleapCommon.int_to_msg_arg_count(n)
        self.assertEqual(len(chr_val), 1)
        self.assertEqual(PrivleapCommon.msg_arg_count_to_int(chr_val), n)

    @given(st.integers())
    def test_encode_range(self, n: int) -> None:
        """Encoding accepts exactly 0..63 and raises ValueError otherwise."""
        if 0 <= n <= 63:
            PrivleapCommon.int_to_msg_arg_count(n)
        else:
            with self.assertRaises(ValueError):
                PrivleapCommon.int_to_msg_arg_count(n)

    @given(st.text(min_size=1, max_size=1))
    def test_decode_never_surprises(self, ch: str) -> None:
        """Decoding a single char either yields 0..63 or raises ValueError --
        never any other exception type."""
        try:
            value = PrivleapCommon.msg_arg_count_to_int(ch)
        except ValueError:
            return
        self.assertTrue(0 <= value <= 63)

    @given(st.text())
    def test_decode_never_raises_unexpectedly(self, s: str) -> None:
        """For any string, decoding raises only ValueError, never e.g.
        IndexError/TypeError."""
        try:
            PrivleapCommon.msg_arg_count_to_int(s)
        except ValueError:
            pass


class TestValidateId(unittest.TestCase):
    """Properties of PrivleapCommon.validate_id."""

    @given(
        st.text(),
        st.sampled_from(list(PrivleapValidateType)),
    )
    @settings(max_examples=400)
    def test_never_raises(self, s: str, vtype: PrivleapValidateType) -> None:
        """validate_id is a total predicate: it returns a bool for any input
        and never raises."""
        self.assertIsInstance(PrivleapCommon.validate_id(s, vtype), bool)

    @given(st.text())
    @settings(max_examples=400)
    def test_accepted_signal_name_is_safe(self, s: str) -> None:
        """A string accepted as a SIGNAL_NAME must be within the documented
        charset and length bound -- so it cannot carry a space, a control byte,
        or non-ASCII into the wire protocol."""
        if PrivleapCommon.validate_id(s, PrivleapValidateType.SIGNAL_NAME):
            self.assertTrue(1 <= len(s) <= 100)
            self.assertRegex(s, r"\A[-A-Za-z0-9_.]+\Z")

    @given(st.text())
    @settings(max_examples=400)
    def test_accepted_user_name_is_safe(self, s: str) -> None:
        """A string accepted as a USER_GROUP_NAME must match the POSIX-ish user
        name charset and length bound."""
        if PrivleapCommon.validate_id(s, PrivleapValidateType.USER_GROUP_NAME):
            self.assertTrue(1 <= len(s) <= 100)
            self.assertRegex(s, r"\A[a-z_][-a-z0-9_]*\$?\Z")


if __name__ == "__main__":
    unittest.main()
