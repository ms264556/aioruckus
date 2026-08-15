"""Live-network tests for the Ruckus One and SmartZone shims.

These tests exercise the read-only shim calls against live Ruckus One and
SmartZone controllers. They are marked ``live`` and deselected by default
(see ``addopts = "-m 'not live'"`` in ``pyproject.toml``).

Credentials are read from environment variables, one set per provider;
tests are skipped for any provider that isn't configured:

    AIORUCKUS_LIVE_SMARTZONE_HOST / AIORUCKUS_LIVE_SMARTZONE_USERNAME / AIORUCKUS_LIVE_SMARTZONE_PASSWORD
    AIORUCKUS_LIVE_RUCKUSONE_HOST / AIORUCKUS_LIVE_RUCKUSONE_USERNAME / AIORUCKUS_LIVE_RUCKUSONE_PASSWORD

For Ruckus One, ``HOST`` is the full tenant URL (e.g.
``https://asia.ruckus.cloud/<tenant-id>/t/``) and ``USERNAME`` / ``PASSWORD``
are the OAuth2 client id / client secret.

For SmartZone, a bare host (no port) is automatically treated as
``<host>:8443`` to match the controller's REST API port.

Only read-only calls are used. Assertions are shape-based rather than
count-based, since live client/AP state changes.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import pytest

from aioruckus.ajaxsession import AjaxSession
from aioruckus.const import StatsLevel

pytestmark = pytest.mark.live


def _shim(name: str, host, username, password) -> dict:
    return {
        "name": name,
        "host": host,
        "username": username,
        "password": password,
        "configured": bool(host and username and password),
    }


def _smartzone_host(host: str | None) -> str | None:
    """Append the SmartZone REST port when the host has no explicit port."""
    if not host:
        return None
    if "://" in host and ":" not in host.split("://", 1)[1].split("/", 1)[0]:
        return f"{host.rstrip('/')}:8443"
    if "://" not in host and ":" not in host.split("/", 1)[0]:
        return f"{host}:8443"
    return host


_SHIMS = [
    _shim(
        "SmartZone",
        _smartzone_host(os.getenv("AIORUCKUS_LIVE_SMARTZONE_HOST")),
        os.getenv("AIORUCKUS_LIVE_SMARTZONE_USERNAME"),
        os.getenv("AIORUCKUS_LIVE_SMARTZONE_PASSWORD"),
    ),
    _shim(
        "RuckusOne",
        os.getenv("AIORUCKUS_LIVE_RUCKUSONE_HOST"),
        os.getenv("AIORUCKUS_LIVE_RUCKUSONE_USERNAME"),
        os.getenv("AIORUCKUS_LIVE_RUCKUSONE_PASSWORD"),
    ),
]


@pytest.fixture(params=_SHIMS, ids=[c["name"] for c in _SHIMS])
def live_shim(request):
    """One shim provider per test, skipping providers without credentials."""
    shim = request.param
    if not shim["configured"]:
        pytest.skip(f"{shim['name']} credentials not configured "
                    f"(set AIORUCKUS_LIVE_{shim['name'].upper()}_* env vars)")
    return shim


@asynccontextmanager
async def _live_session(shim: dict):
    """Open a live controller session and yield the shim API."""
    async with AjaxSession.async_create(
        shim["host"], shim["username"], shim["password"]
    ) as session:
        yield session.api


@pytest.fixture
def live_shim_api(live_shim):
    """Factory for a live-session async context manager."""
    return lambda: _live_session(live_shim)


@pytest.mark.asyncio
async def test_shim_aps(live_shim_api):
    """Shim AP list parses to AP dicts with mac/devname/version/serial."""
    async with live_shim_api() as api:
        aps = await api.get_aps()
        assert isinstance(aps, list)
        for ap in aps:
            assert isinstance(ap, dict)
            assert ap.get("mac")
            assert ap.get("devname")


@pytest.mark.asyncio
async def test_shim_wlans(live_shim_api):
    """Shim WLAN list parses to WLAN dicts with id/name."""
    async with live_shim_api() as api:
        wlans = await api.get_wlans()
        assert isinstance(wlans, list)
        for wlan in wlans:
            assert isinstance(wlan, dict)
            assert "id" in wlan
            assert "name" in wlan


@pytest.mark.asyncio
async def test_shim_system_info(live_shim_api):
    """Shim system info includes identity and sysinfo sections."""
    async with live_shim_api() as api:
        system_info = await api.get_system_info()
        assert isinstance(system_info, dict)
        assert "identity" in system_info
        assert "sysinfo" in system_info
        assert "version" in system_info["sysinfo"]


@pytest.mark.asyncio
async def test_shim_mesh_info(live_shim_api):
    """Shim mesh info exposes a display name."""
    async with live_shim_api() as api:
        mesh = await api.get_mesh_info()
        assert isinstance(mesh, dict)
        assert mesh.get("name")


@pytest.mark.asyncio
async def test_shim_active_clients_stats_levels(live_shim_api):
    """Shim active clients accept StatsLevel/bool like the base class."""
    async with live_shim_api() as api:
        for stats_level in (StatsLevel.L1, StatsLevel.L2, StatsLevel.L3, True, False):
            clients = await api.get_active_clients(stats_level)
            assert isinstance(clients, list)
            for client in clients:
                assert isinstance(client, dict)
                assert client.get("mac")


@pytest.mark.asyncio
async def test_shim_ap_stats_stats_levels(live_shim_api):
    """Shim AP stats accept StatsLevel/bool like the base class."""
    async with live_shim_api() as api:
        for stats_level in (StatsLevel.L1, StatsLevel.L2, StatsLevel.L3, True, False):
            aps = await api.get_ap_stats(stats_level)
            assert isinstance(aps, list)
            for ap in aps:
                assert isinstance(ap, dict)
                assert ap.get("mac")


@pytest.mark.asyncio
async def test_shim_blocked_client_macs(live_shim_api):
    """Shim blocked-client list parses to MAC rules."""
    async with live_shim_api() as api:
        blocked = await api.get_blocked_client_macs()
        assert isinstance(blocked, list)
        for rule in blocked:
            assert isinstance(rule, dict)
            assert rule.get("mac")


@pytest.mark.asyncio
async def test_shim_unsupported_base_helpers(live_shim_api):
    """Unsupported base AJAX helpers fail with NotImplementedError."""
    async with live_shim_api() as api:
        with pytest.raises(NotImplementedError):
            await api._cmdstat_noparse("<ajax-request/>")
        with pytest.raises(NotImplementedError):
            await api._conf_noparse("<ajax-request/>")
        with pytest.raises(NotImplementedError):
            await api._get_conf(object())
