#!/usr/bin/python3

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""privleapd tolerates an action whose TargetUser/TargetGroup does not exist:
it skips just that action instead of failing the entire config load.

Regression: on a minimal / no-tor Kicksecure the systemcheck privleap actions
reference the absent 'debian-tor' account, which previously raised a fatal
'Failed initial config load!' and took down the whole privilege framework (and
with it systemcheck's leaprun-based system-ready check).

Self-contained: uses 'root' (always present) and a bogus name (never present),
so it needs neither root nor fixture accounts. Run with:
  python3 -m unittest privleap.tests.test_target_missing
"""

import os
import tempfile
import unittest
from pathlib import Path

from privleap.privleap import (
    PrivleapAction,
    PrivleapActionTargetMissingError,
    PrivleapCommon,
)

## A name that must not resolve to a real account/group.
BOGUS = "nonexistent-privleap-test-target-xyz"


class TargetMissingSkipTest(unittest.TestCase):
    def test_init_raises_dedicated_error_on_missing_target_user(self) -> None:
        with self.assertRaises(PrivleapActionTargetMissingError):
            PrivleapAction("act", "/bin/true", ["root"], [], BOGUS, None)

    def test_append_if_runnable_skips_missing_target(self) -> None:
        actions: list = []
        PrivleapAction.append_if_runnable(
            actions, "act", "/bin/true", ["root"], [], BOGUS, None
        )
        self.assertEqual(actions, [])

    def test_init_raises_dedicated_error_on_missing_target_group(self) -> None:
        ## Symmetric to the TargetUser path: a valid user but a bogus group.
        with self.assertRaises(PrivleapActionTargetMissingError):
            PrivleapAction("act", "/bin/true", ["root"], [], "root", BOGUS)

    def test_append_if_runnable_keeps_valid_target(self) -> None:
        actions: list = []
        PrivleapAction.append_if_runnable(
            actions, "act", "/bin/true", ["root"], [], "root", None
        )
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].action_name, "act")

    def test_append_if_runnable_does_not_swallow_real_valueerror(self) -> None:
        ## Invariant: the skip path must catch ONLY the missing-target subclass,
        ## never widen to bare ValueError. A genuine config error (here: empty
        ## command) must still propagate, not be silently dropped.
        actions: list = []
        with self.assertRaises(ValueError) as caught:
            PrivleapAction.append_if_runnable(
                actions, "act", None, ["root"], [], "root", None
            )
        self.assertNotIsInstance(
            caught.exception, PrivleapActionTargetMissingError
        )
        self.assertEqual(actions, [])

    @unittest.skipUnless(
        os.geteuid() == 0,
        "parse_config_file requires a root:root-owned config file",
    )
    def test_parse_config_skips_missing_target_action_not_fatal(self) -> None:
        config = (
            "[action:valid-act]\n"
            "Command=/bin/true\n"
            "AuthorizedUsers=root\n"
            "TargetUser=root\n"
            "\n"
            "[action:tor-act]\n"
            "Command=/bin/true\n"
            "AuthorizedUsers=root\n"
            f"TargetUser={BOGUS}\n"
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".conf", delete=False
        ) as handle:
            handle.write(config)
            path = Path(handle.name)
        try:
            ## parse_config_file requires the file be root:root-owned; as root
            ## the egid may not be 0, so set it explicitly rather than rely on it.
            os.chown(path, 0, 0)
            result = PrivleapCommon.parse_config_file(path)
        finally:
            path.unlink()
        ## A fatal parse error returns a str; success returns a ConfigData tuple.
        self.assertNotIsInstance(result, str)
        action_names = [action.action_name for action in result[0]]
        self.assertIn("valid-act", action_names)
        self.assertNotIn("tor-act", action_names)


if __name__ == "__main__":
    unittest.main()
