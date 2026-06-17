"""bp config — Burp config stubs + extensions listing. See docs/CLI.md + SPEC.md §6.10.

Commands
--------
bp config get project      GET  /config/project   (stub → {"type":"project"})
bp config get user         GET  /config/user       (stub → {"type":"user"})
bp config set project      PUT  /config/project    (echo-stub, no durable write)
bp config set user         PUT  /config/user       (echo-stub, no durable write)
bp ext                     GET  /extensions        (self-metadata; total always 1)

Kotlin DTOs (§6.10):
  ConfigUpdateRequest { config: Map<String, String> }

Caveats (surfaced to stderr per SPEC §6.10):
  - GET /config/{project,user} are stubs: they return a hardcoded map
    {"type":"project"} / {"type":"user"} — NOT real Burp project/user settings.
  - PUT /config/{project,user} echo the payload without writing to Burp.
    No setting is persisted; changes are lost immediately.
  - GET /extensions is mounted at the root path /extensions (not /config/extensions).
    Montoya only allows inspection of the active extension → total is always 1.
"""

from __future__ import annotations

import json as _json
from typing import Annotated, Any

import typer

from bp.cliutil import EXIT_USAGE, run

# ---------------------------------------------------------------------------
# config sub-typer  (bp config get … / bp config set …)
# ---------------------------------------------------------------------------

_CONFIG_STUB_WARNING = (
    "warning: /config/{project,user} endpoints are stubs — GET returns a hardcoded map "
    "and PUT echoes the payload without writing to Burp. No setting is persisted."
)

sub = typer.Typer(
    no_args_is_help=True,
    help="Burp config stubs: get/set project or user config (see caveats).",
)

# -- bp config get -----------------------------------------------------------

config_get = typer.Typer(
    no_args_is_help=True,
    help="Get project or user config (stub — returns hardcoded map).",
)
sub.add_typer(config_get, name="get")


@config_get.command("project")
def config_get_project(ctx: typer.Context) -> None:
    """Get project config (STUB — returns hardcoded {\"type\":\"project\"}).

    The server returns a fixed map regardless of actual Burp project settings.
    Do not rely on this output for real configuration values.
    """
    typer.echo(_CONFIG_STUB_WARNING, err=True)
    run(ctx, lambda c: c.get("/config/project"))


@config_get.command("user")
def config_get_user(ctx: typer.Context) -> None:
    """Get user config (STUB — returns hardcoded {\"type\":\"user\"}).

    The server returns a fixed map regardless of actual Burp user settings.
    Do not rely on this output for real configuration values.
    """
    typer.echo(_CONFIG_STUB_WARNING, err=True)
    run(ctx, lambda c: c.get("/config/user"))


# -- bp config set -----------------------------------------------------------

config_set = typer.Typer(
    no_args_is_help=True,
    help="Set project or user config (echo-stub — no durable write to Burp).",
)
sub.add_typer(config_set, name="set")


def _parse_config_json(raw: str) -> dict[str, str]:
    """Parse --json STR into a Map<String,String> (ConfigUpdateRequest.config)."""
    try:
        parsed = _json.loads(raw)
    except _json.JSONDecodeError as exc:
        typer.echo(f"error: --json is not valid JSON: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    if not isinstance(parsed, dict):
        typer.echo("error: --json must be a JSON object (Map<String,String>).", err=True)
        raise typer.Exit(EXIT_USAGE)
    # Coerce values to str to match ConfigUpdateRequest { config: Map<String,String> }
    return {str(k): str(v) for k, v in parsed.items()}


@config_set.command("project")
def config_set_project(
    ctx: typer.Context,
    json_str: Annotated[
        str,
        typer.Option(
            "--json",
            metavar="STR",
            help='JSON object to PUT as ConfigUpdateRequest.config, e.g. \'{"key":"value"}\'.',
        ),
    ],
) -> None:
    """Set project config (ECHO-STUB — PUT is accepted but NOT written to Burp).

    The server echoes the payload without persisting any setting.
    Payload must be a JSON object matching ConfigUpdateRequest { config: Map<String,String> }.
    """
    typer.echo(_CONFIG_STUB_WARNING, err=True)
    config_map = _parse_config_json(json_str)
    body: dict[str, Any] = {"config": config_map}

    def _do(c: Any) -> Any:
        return c._request("PUT", "/config/project", json=body)

    run(ctx, _do)


@config_set.command("user")
def config_set_user(
    ctx: typer.Context,
    json_str: Annotated[
        str,
        typer.Option(
            "--json",
            metavar="STR",
            help='JSON object to PUT as ConfigUpdateRequest.config, e.g. \'{"key":"value"}\'.',
        ),
    ],
) -> None:
    """Set user config (ECHO-STUB — PUT is accepted but NOT written to Burp).

    The server echoes the payload without persisting any setting.
    Payload must be a JSON object matching ConfigUpdateRequest { config: Map<String,String> }.
    """
    typer.echo(_CONFIG_STUB_WARNING, err=True)
    config_map = _parse_config_json(json_str)
    body: dict[str, Any] = {"config": config_map}

    def _do(c: Any) -> Any:
        return c._request("PUT", "/config/user", json=body)

    run(ctx, _do)


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register the 'config' group and the flat 'ext' command onto *app*."""
    app.add_typer(sub, name="config")

    # bp ext — mounted at root /extensions (not /config/extensions per SPEC §6.10)
    @app.command("ext")
    def ext(ctx: typer.Context) -> None:
        """List loaded Burp extensions (self-metadata only; total is always 1).

        GET /extensions — mounted at the root path, not under /config.
        Montoya only allows inspection of the currently-active extension, so
        'total' is always 1 regardless of how many extensions are loaded in Burp.
        """
        typer.echo(
            "note: /extensions only reports the active extension; total is always 1.",
            err=True,
        )
        run(ctx, lambda c: c.get("/extensions"))
