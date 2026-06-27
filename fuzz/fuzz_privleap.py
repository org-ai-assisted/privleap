#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris (libFuzzer) coverage-guided fuzz harness for privleap's server-side
wire-protocol parser.

This is the only privleap code path an unprivileged local user can reach by
writing bytes to their own comm socket, so it is where a parser bug could turn
attacker input into a daemon crash (DoS) or a mis-parsed message. Atheris
mutates inputs guided by the coverage it observes inside privleap.privleap,
reaching deep parser branches a blind generator would rarely hit.

Each input is split into a socket-direction bit and a raw frame, fed to a real
server-side PrivleapSession.get_msg() over a socketpair (half-closed so the
parser sees EOF, never a real timeout), and classified against the parser
contract:

  * a controlled rejection (ValueError / ConnectionAbortedError /
    socket.timeout) or a legal, well-formed message -> not a finding;
  * any other exception propagates, so Atheris reports it as a crash;
  * a returned message of a type illegal for that socket, or with fields that
    fail re-validation, is raised as a type-confusion finding.

libFuzzer's own -timeout catches a parser hang. No root, no network, no live
privleapd. Local run (with `pip install atheris`):
    PYTHONPATH=usr/lib/python3/dist-packages \
      python3 fuzz/fuzz_privleap.py -max_total_time=60 [corpus_dir]
"""

import os
import pwd
import socket
import sys

import atheris

with atheris.instrument_imports():
    from privleap.privleap import (
        PrivleapCommon,
        PrivleapSession,
        PrivleapValidateType,
    )


## Message types legal to RECEIVE on each server-side socket; anything else
## coming back from get_msg() is a type-confusion finding.
COMM_RECV: tuple[str, ...] = ("SIGNAL", "ACCESS_CHECK", "TERMINATE")
CONTROL_RECV: tuple[str, ...] = ("CREATE", "DESTROY", "RELOAD")

## A server-side comm session attributes the connection to an existing account;
## any real account works since the parser does not depend on which one.
_USER: str = pwd.getpwuid(os.getuid()).pw_name


def _fields_ok(msg: object) -> bool:
    """Re-validate an accepted message's fields with the senders' own rules."""

    name: str = msg.name  # type: ignore[attr-defined]
    if name == "SIGNAL":
        return PrivleapCommon.validate_id(
            msg.signal_name,  # type: ignore[attr-defined]
            PrivleapValidateType.SIGNAL_NAME,
        )
    if name in ("CREATE", "DESTROY"):
        return PrivleapCommon.validate_id(
            msg.user_name,  # type: ignore[attr-defined]
            PrivleapValidateType.USER_GROUP_NAME,
        )
    if name == "ACCESS_CHECK":
        names = msg.signal_name_list  # type: ignore[attr-defined]
        if not 1 <= len(names) <= 63:
            return False
        return all(
            PrivleapCommon.validate_id(n, PrivleapValidateType.SIGNAL_NAME)
            for n in names
        )
    ## TERMINATE / RELOAD carry no fields; fail closed for anything unexpected.
    return name in ("TERMINATE", "RELOAD")


def _drive(raw: bytes, control: bool) -> None:
    """Feed ``raw`` to a real server-side parser; raise only on a finding."""

    cli: socket.socket
    srv: socket.socket
    cli, srv = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            session = PrivleapSession(
                srv,
                user_name=None if control else _USER,
                is_control_session=control,
            )
        except Exception:  # pylint: disable=broad-exception-caught
            ## Session setup should not fail for a real user; not a parser bug.
            return

        try:
            cli.sendall(raw)
        except OSError:
            pass
        try:
            cli.shutdown(socket.SHUT_WR)
        except OSError:
            pass

        legal: tuple[str, ...] = CONTROL_RECV if control else COMM_RECV
        try:
            msg = session.get_msg()
        except (ValueError, ConnectionAbortedError, socket.timeout):
            return  ## controlled rejection -- the parser said "no" cleanly

        if msg.name not in legal:
            raise RuntimeError(
                f"TYPE CONFUSION: received {msg.name!r} on a "
                f"{'control' if control else 'comm'} socket; input={raw!r}"
            )
        if not _fields_ok(msg):
            raise RuntimeError(
                f"ILL-FORMED accepted {msg.name!r} message; input={raw!r}"
            )
    finally:
        try:
            cli.close()
        finally:
            srv.close()


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris contract name)
    """Atheris entry point: one fuzz input -> one parse attempt."""

    fdp = atheris.FuzzedDataProvider(data)
    control: bool = fdp.ConsumeBool()
    raw: bytes = fdp.ConsumeBytes(fdp.remaining_bytes())
    _drive(raw, control)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
