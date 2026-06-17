"""bp proxynav commands — flat top-level proxy navigation commands (docs/CLI.md §proxy).

Exposes (all FLAT on the root app per CLI.md §Principe):
  bp req <id>              GET /proxy/history/{id}
  bp ws                    GET /proxy/websocket/history
  bp intercept on|off|forward|drop   POST /proxy/intercept/{enable,disable,forward,drop}

Stub caveats (surfaced to stderr per SPEC §6.2):
  - GET /proxy/intercept status is a stub: always returns {enabled:false}; not used here.
  - POST /proxy/intercept/forward is a stub: returns {forwarded:true} but is a no-op.
  - POST /proxy/intercept/drop   is a stub: returns {dropped:true}  but is a no-op.
"""

from __future__ import annotations

from typing import Annotated

import typer

from bp.cliutil import run


# ---------------------------------------------------------------------------
# bp req <id>   →   GET /proxy/history/{id}
# ---------------------------------------------------------------------------
def req(
    ctx: typer.Context,
    id: Annotated[int, typer.Argument(metavar="ID", help="Absolute proxy-history index.")],
) -> None:
    """Fetch a single proxy-history entry by its absolute index."""
    run(ctx, lambda c: c.get(f"/proxy/history/{id}"))


# ---------------------------------------------------------------------------
# bp ws   →   GET /proxy/websocket/history
# ---------------------------------------------------------------------------
def ws(ctx: typer.Context) -> None:
    """List WebSocket message history (direction + payload).

    Note: the 'timestamp' field reflects the moment of the API call,
    not the original capture time (SPEC §6.2 flag).
    """
    run(ctx, lambda c: c.get("/proxy/websocket/history"))


# ---------------------------------------------------------------------------
# bp intercept on|off|forward|drop   →   POST /proxy/intercept/{action}
# ---------------------------------------------------------------------------
_INTERCEPT_ACTIONS = ("on", "off", "forward", "drop")
_STUBS = {"forward", "drop"}
_ACTION_TO_PATH = {
    "on": "/proxy/intercept/enable",
    "off": "/proxy/intercept/disable",
    "forward": "/proxy/intercept/forward",
    "drop": "/proxy/intercept/drop",
}


def intercept(
    ctx: typer.Context,
    action: Annotated[
        str,
        typer.Argument(
            metavar="on|off|forward|drop",
            help="on=enable, off=disable, forward/drop (stubs — no-op server-side).",
        ),
    ],
) -> None:
    """Control the Burp proxy intercept state.

    \\b
    STUB CAVEAT: 'forward' and 'drop' are server-side stubs.
    The server returns {forwarded:true} / {dropped:true} but performs no real action.
    GET /proxy/intercept status is also a stub (always {enabled:false}); it is not
    called here. See SPEC §6.2 for details.
    """
    if action not in _INTERCEPT_ACTIONS:
        typer.echo(
            f"error: intercept action must be one of {_INTERCEPT_ACTIONS!r}, got {action!r}",
            err=True,
        )
        raise typer.Exit(2)

    if action in _STUBS:
        typer.echo(
            f"warning: '{action}' is a server-side stub — the server acknowledges the "
            "request but performs no real action (SPEC §6.2).",
            err=True,
        )

    path = _ACTION_TO_PATH[action]
    run(ctx, lambda c: c.post(path))


# ---------------------------------------------------------------------------
# Registration hook — called by bp.cli._register_command_groups()
# ---------------------------------------------------------------------------
def register(app: typer.Typer) -> None:
    """Register req, ws, intercept as FLAT top-level commands on *app*."""
    app.command(name="req")(req)
    app.command(name="ws")(ws)
    app.command(name="intercept")(intercept)
