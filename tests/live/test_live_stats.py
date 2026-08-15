"""Live-network tests against real ZoneDirector / Unleashed controllers.

These tests exercise the read-only stats/configuration calls against live
controllers. They are marked ``live`` and deselected by default (see
``addopts = "-m 'not live'"`` in ``pyproject.toml``), so a plain test run
passes completely without access to live devices -- as required by distro
builds / CI. Run them explicitly with ``pytest -m live``.

Credentials are read from environment variables, one set per provider; tests
are skipped for any provider that isn't configured:

    AIORUCKUS_LIVE_ZD_HOST / AIORUCKUS_LIVE_ZD_USERNAME / AIORUCKUS_LIVE_ZD_PASSWORD
    AIORUCKUS_LIVE_UNLEASHED_HOST / AIORUCKUS_LIVE_UNLEASHED_USERNAME / AIORUCKUS_LIVE_UNLEASHED_PASSWORD

The plain ``AIORUCKUS_LIVE_HOST`` / ``AIORUCKUS_LIVE_USERNAME`` /
``AIORUCKUS_LIVE_PASSWORD`` variables are still honoured as a fallback for
the ZoneDirector provider.

Only read-only calls are used (no conf/docmd mutations). Assertions are
shape-based rather than count-based, since live client/AP state changes.
"""

import os
from contextlib import asynccontextmanager

import pytest

from aioruckus.ajaxsession import AjaxSession

pytestmark = pytest.mark.live


def _controller(name: str, host, username, password) -> dict:
    return {
        "name": name,
        "host": host,
        "username": username,
        "password": password,
        "configured": bool(host and username and password),
    }


_CONTROLLERS = [
    _controller(
        "ZoneDirector",
        os.getenv("AIORUCKUS_LIVE_ZD_HOST") or os.getenv("AIORUCKUS_LIVE_HOST"),
        os.getenv("AIORUCKUS_LIVE_ZD_USERNAME") or os.getenv("AIORUCKUS_LIVE_USERNAME"),
        os.getenv("AIORUCKUS_LIVE_ZD_PASSWORD") or os.getenv("AIORUCKUS_LIVE_PASSWORD"),
    ),
    _controller(
        "Unleashed",
        os.getenv("AIORUCKUS_LIVE_UNLEASHED_HOST"),
        os.getenv("AIORUCKUS_LIVE_UNLEASHED_USERNAME"),
        os.getenv("AIORUCKUS_LIVE_UNLEASHED_PASSWORD"),
    ),
]


@pytest.fixture(params=_CONTROLLERS, ids=[c["name"] for c in _CONTROLLERS])
def live_controller(request):
    """One controller per test, skipping providers without credentials."""
    controller = request.param
    if not controller["configured"]:
        pytest.skip(f"{controller['name']} credentials not configured "
                    f"(set AIORUCKUS_LIVE_{controller['name'].upper()}_* env vars)")
    return controller


@asynccontextmanager
async def _live_session(controller: dict):
    """Open a live controller session and yield the API."""
    async with AjaxSession.async_create(
        controller["host"], controller["username"], controller["password"]
    ) as session:
        yield session.api


@pytest.fixture
def live_api(live_controller):
    """Factory for a live-session async context manager."""
    return lambda: _live_session(live_controller)


def _assert_no_wrapper_leak(items: list) -> None:
    """Regression guard: raw response wrappers must not leak into results.

    Some controllers return an id that is only a session tag (e.g. 'DEH')
    rather than a payload key; the payload navigation must still unwrap the
    ``apstamgr-stat`` wrapper.
    """
    assert isinstance(items, list)
    for item in items:
        assert isinstance(item, dict)
        assert "apstamgr-stat" not in item
        assert "id" not in item or "type" not in item


# ---------------------------------------------------------------------------
# Stats calls
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_system_info(live_api):
    """System info parses into sections including identity and sysinfo."""
    async with live_api() as api:
        system_info = await api.get_system_info()
        assert isinstance(system_info, dict)
        assert "identity" in system_info
        assert "sysinfo" in system_info
        assert "version" in system_info["sysinfo"]


@pytest.mark.asyncio
async def test_active_clients(live_api):
    """Active clients parse to a list of client dicts (no wrapper leak)."""
    async with live_api() as api:
        _assert_no_wrapper_leak(await api.get_active_clients())


@pytest.mark.asyncio
async def test_inactive_clients(live_api):
    """Inactive clients parse to a list of client dicts (no wrapper leak)."""
    async with live_api() as api:
        _assert_no_wrapper_leak(await api.get_inactive_clients())


@pytest.mark.asyncio
async def test_ap_stats(live_api):
    """AP statistics parse to a list of AP dicts (no wrapper leak)."""
    async with live_api() as api:
        ap_stats = await api.get_ap_stats()
        _assert_no_wrapper_leak(ap_stats)
        assert ap_stats, "expected at least one AP on the live controller"


@pytest.mark.asyncio
async def test_ap_group_stats(live_api):
    """AP group statistics parse to a list of AP group dicts."""
    async with live_api() as api:
        ap_groups = await api.get_ap_group_stats()
        assert isinstance(ap_groups, list)
        for group in ap_groups:
            assert isinstance(group, dict)
            assert "id" in group
            assert "name" in group


@pytest.mark.asyncio
async def test_vap_stats(live_api):
    """VAP statistics parse to a list of VAP dicts."""
    async with live_api() as api:
        vaps = await api.get_vap_stats()
        assert isinstance(vaps, list)
        for vap in vaps:
            assert isinstance(vap, dict)


@pytest.mark.asyncio
async def test_wlan_group_stats(live_api):
    """WLAN group statistics parse to a list of WLAN group dicts."""
    async with live_api() as api:
        wlan_groups = await api.get_wlan_group_stats()
        assert isinstance(wlan_groups, list)
        for group in wlan_groups:
            assert isinstance(group, dict)
            assert "id" in group
            assert "name" in group


@pytest.mark.asyncio
async def test_dpsk_stats(live_api):
    """DPSK statistics parse to a list of DPSK dicts."""
    async with live_api() as api:
        dpsks = await api.get_dpsk_stats()
        assert isinstance(dpsks, list)
        for dpsk in dpsks:
            assert isinstance(dpsk, dict)


@pytest.mark.asyncio
async def test_active_rogues(live_api):
    """Active rogue devices parse to a list of rogue dicts."""
    async with live_api() as api:
        rogues = await api.get_active_rogues()
        assert isinstance(rogues, list)
        for rogue in rogues:
            assert isinstance(rogue, dict)


@pytest.mark.asyncio
async def test_alarms(live_api):
    """Alarms parse to a list of alarm dicts."""
    async with live_api() as api:
        alarms = await api.get_alarms()
        assert isinstance(alarms, list)
        for alarm in alarms:
            assert isinstance(alarm, dict)


@pytest.mark.asyncio
async def test_events(live_api):
    """Events parse to a list of event dicts."""
    async with live_api() as api:
        events = await api.get_events()
        assert isinstance(events, list)
        for event in events:
            assert isinstance(event, dict)


# ---------------------------------------------------------------------------
# Config calls (smoke checks that live getconf also works)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_aps_config(live_api):
    """AP config parses to a list of AP dicts with mac addresses."""
    async with live_api() as api:
        aps = await api.get_aps()
        assert isinstance(aps, list)
        assert aps
        for ap in aps:
            assert isinstance(ap, dict)
            assert "mac" in ap


@pytest.mark.asyncio
async def test_wlans_config(live_api):
    """WLAN config parses to a list of WLAN dicts with resolved links."""
    async with live_api() as api:
        wlans = await api.get_wlans()
        assert isinstance(wlans, list)
        assert wlans
        for wlan in wlans:
            assert isinstance(wlan, dict)
            assert "id" in wlan
            assert "name" in wlan


@pytest.mark.asyncio
async def test_mesh_info(live_api):
    """Mesh config parses to a mesh dict with name and psk."""
    async with live_api() as api:
        mesh = await api.get_mesh_info()
        assert isinstance(mesh, dict)
        assert "name" in mesh
        assert "psk" in mesh
