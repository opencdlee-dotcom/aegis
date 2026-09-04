"""Run this suite as if it were on another body. Opt-in pytest plugin.

    PYTHONPATH=tests python -m pytest tests/ -q -p simbody              # linux (default)
    PYTHONPATH=tests SIM_BODY=win python -m pytest tests/ -q -p simbody
    PYTHONPATH=tests SIM_BODY=mac python -m pytest tests/ -q -p simbody

(`PYTHONPATH=tests` is not decoration: pytest imports a `-p` plugin before it
puts anything on sys.path, so without it you get `No module named 'simbody'`.)

Why this exists, in one sentence: the defects that cost this project whole CI
cycles are ones where a fixture hard-codes one body's vocabulary or path shape,
and a macOS run cannot fail on them BY CONSTRUCTION.

It has now happened twice. 2026-08-24, tests/test_outbound_subject.py stubbed
`{"trust": "adhoc"}` while promising "on every OS" -- 12/12 failures on Windows,
24 minutes of CI to find. Same day, `_prec(..., trust="developer-id")` held up
test_custody.py's `publisher-stable` assertion on Linux, and the macOS run that
gated the push was a no-op on the very lines that changed. Both times a harness
like this reproduced the failure locally in seconds; both times it was written
ad hoc and thrown away, so the third occurrence would have paid full price
again. Hence a file in the repo rather than a command in a transcript.

HOW TO USE IT HONESTLY -- the absolute failure count under simulation is NOT
meaningful. Plenty of cases fail here for reasons that have nothing to do with
your change (real macOS paths, a live `codesign`, `/private/tmp` firmlinks).
What is meaningful is the DIFF against the same run on your merge base:

    base=~/simbody-base && rm -rf "$base" && mkdir -p "$base"   # NOT mktemp -d
    git archive "$(git merge-base origin/main HEAD)" | tar -x -C "$base"
    run() { (cd "$1" && SIM_REPO="$1" SIM_BODY="$2" PYTHONPATH="$PWD/tests" \
            python -m pytest tests/ -q -p simbody 2>&1 | grep '^FAILED' | sed 's/ - .*//' | sort); }
    diff <(run "$base" linux) <(run . linux)      # empty => no new failures

The base tree must NOT live under /tmp. Aegis classifies volatile paths
differently, so a base checkout in a temp dir changes the very verdicts being
compared -- that is not hypothetical, it produced two phantom "fixes" here.
The recipe above said `mktemp -d` until 2026-09-03. CI now runs this diff for
both `win` and `mac` on every push and PR (.github/workflows/ci.yml,
job `simbody-diff`), so it is a gate rather than a habit.

WHAT IT DOES NOT SIMULATE, and never will: os.sep, path parsing, case
sensitivity, file locking, subprocess behaviour, or anything the real kernel
decides. It flips `aegis`'s platform flags before conftest binds its per-body
mirrors, and makes conftest's platform gating agree. That covers the class of
defect above -- a verdict, a flag, a branch -- and nothing else. A green run
here is not a substitute for the Windows leg; it is the check that stops you
sending the Windows leg something it will obviously reject.
"""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.environ.get("SIM_REPO") or os.path.dirname(_HERE))

import aegis  # noqa: E402

BODY = os.environ.get("SIM_BODY", "linux")
if BODY not in ("mac", "win", "linux"):
    raise SystemExit("SIM_BODY must be mac, win or linux (got %r)" % BODY)

# Before conftest imports: SUSPICIOUS_TRUST / PUBLISHER_TRUST are bound from
# these flags at conftest import time, so flipping them later proves nothing.
aegis.IS_WIN = BODY == "win"
aegis.IS_LINUX = BODY == "linux"
aegis.IS_MAC = BODY == "mac"


def pytest_report_header(config):
    return ("simbody: running as %r — flags only, NOT the real kernel; compare "
            "the FAILED set against your merge base, not against zero" % BODY)


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    """Make conftest's platform gating agree with the simulated body.

    tryfirst so this lands before conftest's own hook reads these globals.
    """
    import conftest
    conftest.IS_MAC = BODY == "mac"
    if BODY != "win":
        conftest.os.name = "posix"
