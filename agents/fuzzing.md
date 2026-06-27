<!--
Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted
-->

# Fuzzing

The untrusted-input surface is an unprivileged local user writing bytes to
their own comm socket (mode `0600`); config files and PAM config are root-owned
and trusted. The fuzzing here targets that surface -- the server-side
wire-protocol parser -- where a bug could become a daemon crash (DoS) or a
mis-parsed message. Two layers, in increasing depth.

## 1. Hypothesis property tests

Lives in `ci/tests/privleap/test_property.py`. **Outside** the Python package
tree on purpose: `debian/privleap.install` ships `usr/*`, so keeping property
tests under `ci/tests/` means they do NOT end up in the installed `.deb`. The
whole-daemon tests still live under
`usr/lib/python3/dist-packages/privleap/tests/` (driven by the autopkgtest).

It asserts invariants of the small, security-relevant pure helpers in
`privleap.privleap`: the argument-count codec round-trips over its whole domain
and rejects everything else without a surprise exception; `validate_id` never
raises and a string it accepts as a signal / user name really is within the
documented charset and length bound (so a validated name cannot smuggle a space
or control byte into the protocol).

Local run (needs `python3-hypothesis` from Debian apt):
```
PYTHONPATH=usr/lib/python3/dist-packages \
  python3 -m pytest --import-mode=importlib \
    ci/tests/privleap/test_property.py
```

## 2. ClusterFuzzLite (Atheris under the hood)

Coverage-guided fuzzing of the server-side parser, orchestrated by
ClusterFuzzLite. Atheris is the engine; ClusterFuzzLite handles the build
(OSS-Fuzz base-builder + `compile_python_fuzzer`), corpus persistence (via
`actions/cache`), crash dedup, SARIF, and PR annotations.

Harnesses live in `fuzz/fuzz_<name>.py`. Configuration:
`.clusterfuzzlite/{Dockerfile,build.sh,project.yaml}`. Workflow:
`.github/workflows/local-python-fuzz.yml` with two jobs:
- `pr` - short fuzz on every PR that touches the Python library, the harnesses,
  or the ClusterFuzzLite config. Findings appear as PR annotations.
- `batch` - longer-budget batch fuzz on schedule + workflow_dispatch. Crashes /
  corpora persist via `actions/cache`.

`fuzz/fuzz_privleap.py` drives a real server-side `PrivleapSession.get_msg()`
over a socketpair and lets only genuine findings escape (an uncontrolled
exception, or an explicitly-raised type confusion / ill-formed accept), which
Atheris reports as crashes; libFuzzer's `-timeout` catches a hang. It imports
only `privleap.privleap` (pure stdlib), so no extra runtime dependency is
needed.

Local run against the harness (no docker, no ClusterFuzzLite - direct Atheris,
useful for iterating; needs `pip install atheris`):
```
PYTHONPATH=usr/lib/python3/dist-packages \
  python3 fuzz/fuzz_privleap.py -max_total_time=60 [corpus_dir]
```

Adding a harness: drop a new `fuzz/fuzz_<name>.py`; `.clusterfuzzlite/build.sh`
loops `compile_python_fuzzer` over every `fuzz/fuzz_*.py`, so it is picked up
automatically.

## Trust footprint

- Hypothesis: Debian apt (`python3-hypothesis`).
- ClusterFuzzLite + Atheris + OSS-Fuzz base-builder: Google. Per-pin provenance
  is in `.github/workflows/local-python-fuzz.yml` and
  `.clusterfuzzlite/Dockerfile`.
