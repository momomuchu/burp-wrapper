"""bp obs — observability commands: 'bp log' and 'bp tag' (STATE-AND-CONFIG §1).

Commands
--------
bp log [--since T] [--until T] [--target H] [--tag X] [--status S] [--limit N]
    Query the run ledger and render matching ops rows.

bp tag <opId> <name>
    Set the tag field on a ledger row identified by opId.

These commands operate against the local ledger (~/.bp/ledger.db) and do NOT
require a running Burp instance.
"""

from __future__ import annotations

from typing import Any

import typer

from bp.config import load as load_config
from bp.ledger import Ledger, QueryFilters
from bp.output import render

sub = typer.Typer(no_args_is_help=False, help="Run ledger: log and tag.")


# ---------------------------------------------------------------------------
# bp log
# ---------------------------------------------------------------------------


@sub.command("log")
def log_cmd(
    ctx: typer.Context,
    since: str | None = typer.Option(
        None,
        "--since",
        metavar="T",
        help="ISO-8601 lower bound for ts (inclusive).",
    ),
    until: str | None = typer.Option(
        None,
        "--until",
        metavar="T",
        help="ISO-8601 upper bound for ts (inclusive).",
    ),
    target: str | None = typer.Option(
        None,
        "--target",
        metavar="H",
        help="Filter by exact target host/url.",
    ),
    tag: str | None = typer.Option(
        None,
        "--tag",
        metavar="X",
        help="Filter by exact tag value.",
    ),
    status: str | None = typer.Option(
        None,
        "--status",
        metavar="S",
        help="Filter by status: ok | error | refused.",
    ),
    limit: int = typer.Option(
        100,
        "--limit",
        metavar="N",
        help="Maximum number of rows to return (default 100).",
    ),
) -> None:
    """Query the run ledger and print matching ops rows.

    Reads from ~/.bp/ledger.db (or BP_LEDGER_PATH).  Does not require Burp.
    """
    cfg = load_config()
    if not cfg.ledger:
        typer.echo("note: ledger is disabled (ledger=off in config).", err=True)
        return

    filters = QueryFilters(
        since=since,
        until=until,
        target=target,
        tag=tag,
        status=status,
        limit=limit,
    )
    with Ledger() as ledger:
        rows = ledger.query(filters)

    # Render via the shared output layer; ctx.obj may not exist in ledger-only context
    fmt = "table"
    fields: list[str] | None = None
    try:
        from bp.cliutil import State

        state: State = ctx.obj
        if state is not None:
            fmt = state.fmt
            fields = state.fields
    except Exception:
        pass

    data: list[dict[str, Any]] = [r.as_dict() for r in rows]
    typer.echo(render(data, fmt, fields=fields))


# ---------------------------------------------------------------------------
# bp tag
# ---------------------------------------------------------------------------


@sub.command("tag")
def tag_cmd(
    ctx: typer.Context,
    op_id: str = typer.Argument(..., metavar="opId", help="Ledger op id to tag."),
    name: str = typer.Argument(..., metavar="name", help="Tag value to set."),
) -> None:
    """Set the tag field on a ledger row by opId.

    bp tag <opId> <name>

    Exits 1 if the opId is not found in the ledger.
    """
    cfg = load_config()
    if not cfg.ledger:
        typer.echo("note: ledger is disabled (ledger=off in config).", err=True)
        return

    with Ledger() as ledger:
        found = ledger.tag(op_id, name)

    if not found:
        typer.echo(f"error: op id {op_id!r} not found in ledger.", err=True)
        raise typer.Exit(1)

    typer.echo(f"tagged {op_id!r} -> {name!r}")


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register 'bp log' and 'bp tag' onto *app*."""
    app.add_typer(sub, name="obs", hidden=True)  # sub-group hidden; commands registered flat

    # Register flat commands directly on app so 'bp log' and 'bp tag' work
    # without the 'obs' prefix.
    @app.command("log")
    def log_flat(
        ctx: typer.Context,
        since: str | None = typer.Option(None, "--since", metavar="T"),
        until: str | None = typer.Option(None, "--until", metavar="T"),
        target: str | None = typer.Option(None, "--target", metavar="H"),
        tag: str | None = typer.Option(None, "--tag", metavar="X"),
        status: str | None = typer.Option(None, "--status", metavar="S"),
        limit: int = typer.Option(100, "--limit", metavar="N"),
    ) -> None:
        """Query the run ledger (bp log [--since --until --target --tag --status --limit])."""
        cfg = load_config()
        if not cfg.ledger:
            typer.echo("note: ledger is disabled (ledger=off in config).", err=True)
            return

        filters = QueryFilters(
            since=since,
            until=until,
            target=target,
            tag=tag,
            status=status,
            limit=limit,
        )
        with Ledger() as ledger:
            rows = ledger.query(filters)

        fmt = "table"
        fields: list[str] | None = None
        try:
            from bp.cliutil import State as _State

            state: _State = ctx.obj
            if state is not None:
                fmt = state.fmt
                fields = state.fields
        except Exception:
            pass

        data: list[dict[str, Any]] = [r.as_dict() for r in rows]
        typer.echo(render(data, fmt, fields=fields))

    @app.command("tag")
    def tag_flat(
        ctx: typer.Context,
        op_id: str = typer.Argument(..., metavar="opId"),
        name: str = typer.Argument(..., metavar="name"),
    ) -> None:
        """Set a tag on a ledger row: bp tag <opId> <name>."""
        cfg = load_config()
        if not cfg.ledger:
            typer.echo("note: ledger is disabled (ledger=off in config).", err=True)
            return

        with Ledger() as ledger:
            found = ledger.tag(op_id, name)

        if not found:
            typer.echo(f"error: op id {op_id!r} not found in ledger.", err=True)
            raise typer.Exit(1)

        typer.echo(f"tagged {op_id!r} -> {name!r}")
