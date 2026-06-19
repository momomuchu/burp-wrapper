"""Tests for bp obs commands (bp log / bp tag). Local-only, no Burp required."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import os


def test_tag_exits_nonzero_when_ledger_disabled() -> None:
    """D2: `bp tag` must fail (exit 1) when the ledger is disabled — the tag was NOT applied.

    Previously it bare-returned (exit 0), so a script checking the exit code believed the tag
    had been written. No Burp needed: tag is a local ledger operation.
    """
    entry = (
        "import os; os.environ['BP_NO_LEDGER']='1'; "
        "import sys; sys.argv=['bp','tag','someop','mytag']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 1, f"expected exit 1 when ledger disabled, got {r.returncode}: {r.stderr}"


# [28] RED — bp log must also exit 1 when ledger is disabled (consistent with bp tag).
def test_log_exits_nonzero_when_ledger_disabled() -> None:
    """`bp log` exits 1 when the ledger is disabled.

    Previously it bare-returned (exit 0), misleading scripts into believing a query succeeded.
    Must be consistent with `bp tag` which already exits 1 for the same condition.
    """
    entry = (
        "import os; os.environ['BP_NO_LEDGER']='1'; "
        "import sys; sys.argv=['bp','log']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 1, f"expected exit 1 when ledger disabled, got {r.returncode}: {r.stderr}"


# [09] RED — bp log must emit ZERO bytes on stdout when the ledger returns zero rows.
# OUTPUT.md §4.4: empty stdout + exit 0 = zero records. typer.echo('') writes '\n' which
# breaks the contract. The fix (guarded echo in log_cmd) must suppress the lone newline.
def test_log_empty_ledger_zero_stdout_bytes() -> None:
    """`bp log` writes zero bytes to stdout when the ledger has no matching rows (exit 0).

    Uses a fresh empty temp ledger via BP_LEDGER_PATH so no rows exist. The zero-records
    contract (OUTPUT.md §4.4) forbids a lone newline on stdout. This is the regression lock
    for the spurious '\\n' emitted by the bare typer.echo(render(...)) on line 90 of obs.py.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger_path = os.path.join(tmpdir, "ledger.db")
        entry = (
            f"import os; os.environ['BP_LEDGER_PATH']={ledger_path!r}; "
            "import sys; sys.argv=['bp','log']; "
            "from bp.cli import cli_main; cli_main()"
        )
        r = subprocess.run([sys.executable, "-c", entry], capture_output=True)
    assert r.returncode == 0, f"expected exit 0 for empty ledger, got {r.returncode}: {r.stderr!r}"
    assert r.stdout == b"", (
        f"expected zero stdout bytes for empty ledger, got {r.stdout!r}"
    )
