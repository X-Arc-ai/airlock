"""Airlock sandbox — run a command whose ONLY network egress is the proxy.

Enforcement tiers (strongest available wins, everything guarded):

* linux-netns  — network namespace + veth pair + nftables ``policy drop``:
  the sandboxed process can reach nothing but the Airlock proxy on the host
  end of the veth. DNS, direct IP, everything else is dropped in-kernel.
* mac-docker / docker — ``docker run`` with proxy env + mitmproxy CA mounted
  (network reachable, but HTTP(S) is steered through the proxy).
* env — plain subprocess with HTTP(S)_PROXY + CA env vars. Weakest tier but
  always works; also the fallback whenever a stronger tier fails to set up.

Public API (per CONTRACTS.md): ``run(cmd, proxy_addr) -> int`` and
``detect_platform() -> str``.
"""
from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import uuid
from pathlib import Path

try:
    from . import config
except ImportError:  # imported as a plain script
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from airlock import config

log = logging.getLogger("airlock.sandbox")

MITM_CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
DOCKER_IMAGE = os.environ.get("AIRLOCK_SANDBOX_IMAGE", "alpine:3")

# veth /30: host side .1 (gateway == where the proxy is reachable), ns side .2
_NET_PREFIX = "10.213"


class SandboxError(RuntimeError):
    """Raised when a strong-isolation tier cannot be set up."""


# ------------------------------------------------------------------- platform

def detect_platform() -> str:
    """Which enforcement tier this machine supports.

    Returns one of: 'linux-netns', 'linux-env', 'mac-docker', 'docker', 'env'.
    """
    sysname = platform.system().lower()
    if sysname == "linux":
        if (hasattr(os, "geteuid") and os.geteuid() == 0
                and shutil.which("ip") and shutil.which("nft")):
            return "linux-netns"
        return "linux-env"
    if sysname == "darwin":
        return "mac-docker" if shutil.which("docker") else "env"
    return "docker" if shutil.which("docker") else "env"


# -------------------------------------------------------------------- helpers

def _split_addr(proxy_addr: str) -> tuple[str, int]:
    host, _, port = str(proxy_addr).strip().rpartition(":")
    if not host:
        host, port = port, str(config.PROXY_PORT)
    return host or "127.0.0.1", int(port)


def _ca_env(prefix_path: str | None = None) -> dict[str, str]:
    """CA-trust env vars for the mitmproxy certificate, if it exists."""
    ca = prefix_path or str(MITM_CA)
    if prefix_path is None and not MITM_CA.exists():
        log.warning("sandbox: mitmproxy CA not found at %s — HTTPS interception "
                    "will fail cert checks until `mitmdump` has run once", MITM_CA)
        return {}
    return {
        "SSL_CERT_FILE": ca,
        "REQUESTS_CA_BUNDLE": ca,
        "CURL_CA_BUNDLE": ca,
        "NODE_EXTRA_CA_CERTS": ca,
    }


def _proxy_env(proxy_url: str) -> dict[str, str]:
    return {
        "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url, "https_proxy": proxy_url,
        "NO_PROXY": "", "no_proxy": "",
        "AIRLOCK": "1",
    }


def _sh(args: list[str], *, input_text: str | None = None) -> None:
    """Run a setup command; raise SandboxError with the real stderr on failure."""
    proc = subprocess.run(args, capture_output=True, text=True,
                          input=input_text, timeout=30)
    if proc.returncode != 0:
        raise SandboxError(f"{' '.join(args)!r} failed rc={proc.returncode}: "
                           f"{proc.stderr.strip() or proc.stdout.strip()}")


# ---------------------------------------------------------------- linux netns

def _run_netns(cmd: list[str], proxy_addr: str) -> int:
    """netns + veth + nftables: only egress is the proxy. Root required."""
    phost, pport = _split_addr(proxy_addr)
    sfx = uuid.uuid4().hex[:6]
    ns = f"airlock-{sfx}"
    veth_host, veth_ns = f"alk0{sfx}"[:15], f"alk1{sfx}"[:15]
    octet = os.getpid() % 250
    net, gw_ip, ns_ip = (f"{_NET_PREFIX}.{octet}.0/30",
                         f"{_NET_PREFIX}.{octet}.1", f"{_NET_PREFIX}.{octet}.2")

    # From inside the namespace, a loopback-bound proxy is reachable only via
    # the host end of the veth (requires the proxy to listen on 0.0.0.0 or on
    # the veth IP — `mitmdump -s airlock/proxy.py` listens on all interfaces
    # by default).
    proxy_ip = gw_ip if phost in ("127.0.0.1", "localhost", "0.0.0.0") else phost

    try:
        _sh(["ip", "netns", "add", ns])
    except SandboxError:
        raise  # nothing to clean up yet

    try:
        _sh(["ip", "link", "add", veth_host, "type", "veth",
             "peer", "name", veth_ns])
        _sh(["ip", "link", "set", veth_ns, "netns", ns])
        _sh(["ip", "addr", "add", f"{gw_ip}/30", "dev", veth_host])
        _sh(["ip", "link", "set", veth_host, "up"])
        _sh(["ip", "-n", ns, "addr", "add", f"{ns_ip}/30", "dev", veth_ns])
        _sh(["ip", "-n", ns, "link", "set", veth_ns, "up"])
        _sh(["ip", "-n", ns, "link", "set", "lo", "up"])
        _sh(["ip", "-n", ns, "route", "add", "default", "via", gw_ip])

        # In-kernel guarantee: inside the ns, drop every packet that is not
        # loopback or TCP to the proxy. No DNS, no direct IP, no side channels.
        nft_rules = f"""
        table inet airlock {{
            chain out {{
                type filter hook output priority 0; policy drop;
                oifname "lo" accept
                ip daddr {proxy_ip} tcp dport {pport} accept
            }}
        }}
        """
        _sh(["ip", "netns", "exec", ns, "nft", "-f", "-"], input_text=nft_rules)

        env = dict(os.environ)
        env.update(_proxy_env(f"http://{proxy_ip}:{pport}"))
        env.update(_ca_env())
        log.info("sandbox[linux-netns]: ns=%s proxy=%s:%s cmd=%r",
                 ns, proxy_ip, pport, cmd)
        proc = subprocess.run(["ip", "netns", "exec", ns] + list(cmd), env=env)
        return proc.returncode
    finally:
        subprocess.run(["ip", "netns", "del", ns],
                       capture_output=True, timeout=30)
        subprocess.run(["ip", "link", "del", veth_host],  # no-op if ns del got it
                       capture_output=True, timeout=30)


# --------------------------------------------------------------------- docker

def _run_docker(cmd: list[str], proxy_addr: str) -> int:
    """docker run with proxy env + CA mount (mac & friends)."""
    phost, pport = _split_addr(proxy_addr)
    if phost in ("127.0.0.1", "localhost", "0.0.0.0"):
        phost = "host.docker.internal"
    proxy_url = f"http://{phost}:{pport}"

    args = ["docker", "run", "--rm",
            "--add-host", "host.docker.internal:host-gateway",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    for k, v in _proxy_env(proxy_url).items():
        args += ["-e", f"{k}={v}"]
    if MITM_CA.exists():
        ca_in = "/airlock/mitmproxy-ca-cert.pem"
        args += ["-v", f"{MITM_CA}:{ca_in}:ro"]
        for k, v in _ca_env(ca_in).items():
            args += ["-e", f"{k}={v}"]
    args += [DOCKER_IMAGE] + list(cmd)
    log.info("sandbox[docker]: image=%s proxy=%s cmd=%r", DOCKER_IMAGE, proxy_url, cmd)
    proc = subprocess.run(args)
    if proc.returncode == 125:  # docker itself failed (no daemon, bad image…)
        raise SandboxError(f"docker run failed rc=125 for image {DOCKER_IMAGE}")
    return proc.returncode


# ------------------------------------------------------------------- env-only

def _run_env(cmd: list[str], proxy_addr: str) -> int:
    """Weakest tier: subprocess with HTTP(S)_PROXY + CA env. Always works."""
    phost, pport = _split_addr(proxy_addr)
    env = dict(os.environ)
    env.update(_proxy_env(f"http://{phost}:{pport}"))
    env.update(_ca_env())
    log.info("sandbox[env]: proxy=%s:%s cmd=%r (env-only — no kernel "
             "enforcement, direct egress is possible)", phost, pport, cmd)
    proc = subprocess.run(list(cmd), env=env)
    return proc.returncode


# ----------------------------------------------------------------- public api

def run(cmd: list[str], proxy_addr: str | None = None) -> int:
    """Run ``cmd`` so its only (enforced) network egress is the Airlock proxy.

    Picks the strongest tier the platform supports and degrades loudly:
    linux-netns -> env, docker -> env. Returns the command's exit code.
    """
    if not cmd:
        raise ValueError("sandbox.run: empty command")
    proxy_addr = proxy_addr or f"127.0.0.1:{config.PROXY_PORT}"
    tier = detect_platform()

    if tier == "linux-netns":
        try:
            return _run_netns(list(cmd), proxy_addr)
        except (SandboxError, OSError, subprocess.SubprocessError) as e:
            log.error("sandbox: netns isolation FAILED (%s) — falling back to "
                      "env-proxy (no kernel enforcement)", e)
    elif tier in ("mac-docker", "docker"):
        try:
            return _run_docker(list(cmd), proxy_addr)
        except (SandboxError, OSError, subprocess.SubprocessError) as e:
            log.error("sandbox: docker isolation FAILED (%s) — falling back to "
                      "env-proxy (no kernel enforcement)", e)

    return _run_env(list(cmd), proxy_addr)
