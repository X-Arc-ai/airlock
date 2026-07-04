"""Airlock CLI — screen / run / protect / ui / bench.

Entry: ``python -m airlock <command>`` (see airlock/__main__.py) or
``airlock <command>`` if installed as a script.

Heavy modules (screener, sandbox, ledger, uvicorn) are imported lazily inside
each command so ``--help`` and ``screen`` stay fast and independent.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import List, Optional

import typer

from . import config

REPO_ROOT = Path(__file__).resolve().parent.parent

app = typer.Typer(
    name="airlock",
    help="Airlock — on-device firewall for AI agents: screen untrusted content, "
         "sandbox commands behind a screening proxy, quarantine attacks.",
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.callback()
def _global(
    model: Optional[str] = typer.Option(
        None, "--model", metavar="TAG",
        help="Screening model tag (e.g. gemma3:4b-it-qat). Sets AIRLOCK_MODEL "
             "for this run and any child process."),
) -> None:
    if model:
        os.environ["AIRLOCK_MODEL"] = model
        config.MODEL = model  # config reads env at import; keep both in sync


# ---------------------------------------------------------------- helpers

def _port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _wait_port(host: str, port: int, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_open(host, port):
            return True
        time.sleep(0.25)
    return False


def _find_mitmdump() -> Optional[str]:
    cand = Path(sys.executable).parent / "mitmdump"
    if cand.exists():
        return str(cand)
    import shutil
    return shutil.which("mitmdump")


# ---------------------------------------------------------------- commands

@app.command()
def screen(
    text: str = typer.Argument(..., help="Untrusted content to screen"),
    source: str = typer.Option("cli", "--source", help="Source label for the trust ledger"),
    record: bool = typer.Option(True, "--record/--no-record",
                                help="Record the verdict to the ledger + live UI feed"),
) -> None:
    """Screen TEXT with the on-device model; print the Verdict as JSON.

    Exit code 0 = allow, 1 = quarantine (scriptable).
    """
    from .screener import screen as _screen

    verdict = _screen(text, source=source)
    try:  # attack-family cosine boost (config.FAMILY_THRESHOLD); fail-soft
        from .families import apply_boost
        verdict = apply_boost(verdict, text)
    except Exception:
        pass

    if record:
        try:
            from .ledger import TrustLedger
            with TrustLedger() as ledger:
                ledger.record(verdict, text)
        except Exception as e:
            typer.secho(f"[airlock] ledger record failed: {e}",
                        fg=typer.colors.YELLOW, err=True)
        try:
            from . import mcp_gateway
            mcp_gateway.post_event(
                "quarantine" if verdict.quarantined() else "screened",
                source, verdict=verdict, preview=text,
                detail="airlock screen (cli)", wait=True)
        except Exception:
            pass  # UI down is fine

    typer.echo(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))
    raise typer.Exit(1 if verdict.quarantined() else 0)


@app.command(context_settings={"allow_extra_args": True,
                               "ignore_unknown_options": True,
                               "help_option_names": ["-h", "--help"]})
def run(
    cmd: List[str] = typer.Argument(..., help="Command to sandbox "
                                    "(use `airlock run -- cmd --flags` for flags)"),
    proxy: bool = typer.Option(True, "--proxy/--no-proxy",
                               help="Auto-start the Airlock screening proxy if "
                                    "none is listening"),
) -> None:
    """Tier-1: run CMD in the sandbox — all egress via the screening proxy."""
    proxy_addr = f"127.0.0.1:{config.PROXY_PORT}"
    started: Optional[subprocess.Popen] = None

    if proxy and not _port_open("127.0.0.1", config.PROXY_PORT):
        mitmdump = _find_mitmdump()
        if not mitmdump:
            typer.secho("[airlock] mitmdump not found in venv/PATH — cannot "
                        "start the proxy", fg=typer.colors.RED, err=True)
            raise typer.Exit(3)
        proxy_script = Path(__file__).resolve().parent / "proxy.py"
        started = subprocess.Popen(
            [mitmdump, "-q", "--listen-host", "127.0.0.1",
             "-p", str(config.PROXY_PORT), "-s", str(proxy_script)],
            cwd=str(REPO_ROOT), env=os.environ.copy())
        if not _wait_port("127.0.0.1", config.PROXY_PORT):
            started.terminate()
            typer.secho(f"[airlock] proxy failed to come up on {proxy_addr}",
                        fg=typer.colors.RED, err=True)
            raise typer.Exit(3)
        typer.secho(f"[airlock] screening proxy up on {proxy_addr}",
                    fg=typer.colors.GREEN, err=True)
    elif _port_open("127.0.0.1", config.PROXY_PORT):
        typer.secho(f"[airlock] using existing proxy on {proxy_addr}",
                    fg=typer.colors.GREEN, err=True)

    from . import sandbox  # LAZY: screen/--help must work without sandbox

    try:
        code = sandbox.run(list(cmd), proxy_addr=proxy_addr)
    finally:
        if started is not None:
            started.terminate()
            try:
                started.wait(timeout=5)
            except subprocess.TimeoutExpired:
                started.kill()
    raise typer.Exit(code)


@app.command()
def protect(
    agent: str = typer.Argument(..., help="claude | codex | opencode"),
) -> None:
    """Tier-2: print setup that wraps AGENT's MCP servers with the Airlock gateway."""
    from . import mcp_gateway
    try:
        typer.echo(mcp_gateway.install(agent))
    except ValueError as e:
        typer.secho(f"[airlock] {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)


@app.command()
def ui(
    open_browser: bool = typer.Option(True, "--open/--no-open",
                                      help="Open the event feed in a browser"),
) -> None:
    """Launch the Airlock live event feed (UI server)."""
    url = f"http://127.0.0.1:{config.UI_PORT}"
    desktop = Path(__file__).resolve().parent / "ui" / "desktop.py"
    if sys.platform == "darwin" and desktop.exists():
        typer.echo(f"[airlock] launching desktop shell ({url})")
        raise typer.Exit(subprocess.call([sys.executable, str(desktop)],
                                         cwd=str(REPO_ROOT)))
    typer.echo(f"[airlock] event feed: {url}")
    if open_browser:
        threading.Timer(1.2, webbrowser.open, args=(url,)).start()
    import uvicorn
    from .ui.server import app as ui_app
    uvicorn.run(ui_app, host="127.0.0.1", port=config.UI_PORT,
                log_level="warning")


@app.command(context_settings={"allow_extra_args": True,
                               "ignore_unknown_options": True,
                               "help_option_names": ["-h", "--help"]})
def bench(ctx: typer.Context) -> None:
    """Run the screening benchmark (bench/run_eval.py); extra args pass through."""
    script = REPO_ROOT / "bench" / "run_eval.py"
    if not script.exists():
        typer.secho(f"[airlock] bench script not found: {script}",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    raise typer.Exit(subprocess.call([sys.executable, str(script), *ctx.args],
                                     cwd=str(REPO_ROOT), env=os.environ.copy()))


if __name__ == "__main__":
    app()
