"""Interface-consistency tests for the Ruckus One and SmartZone shims.

The shims subclass :class:`RuckusAjaxApi`; they must accept the same
``stats_level`` argument as the base class for ``get_active_clients`` /
``get_ap_stats`` (even though the level is ignored), and every unsupported
base AJAX method must fail with ``NotImplementedError`` rather than leaking
the parent's private-session ``AssertionError``.
"""

import pytest

from aioruckus.const import StatsLevel

pytestmark = pytest.mark.asyncio

STATS_LEVELS = (StatsLevel.L1, StatsLevel.L2, StatsLevel.L3, True, False)


@pytest.mark.parametrize("stats_level", STATS_LEVELS)
async def test_r1_active_clients_accepts_stats_level(create_r1_session, stats_level):
    """Ruckus One get_active_clients accepts StatsLevel/bool like the base."""
    async with create_r1_session() as session:
        clients = await session.api.get_active_clients(stats_level)
        assert len(clients) == 2


@pytest.mark.parametrize("stats_level", STATS_LEVELS)
async def test_r1_ap_stats_accepts_stats_level(create_r1_session, stats_level):
    """Ruckus One get_ap_stats accepts StatsLevel/bool like the base."""
    async with create_r1_session() as session:
        aps = await session.api.get_ap_stats(stats_level)
        assert len(aps) == 2


@pytest.mark.parametrize("stats_level", STATS_LEVELS)
async def test_sz_active_clients_accepts_stats_level(create_sz_session, stats_level):
    """SmartZone get_active_clients accepts StatsLevel/bool like the base."""
    async with create_sz_session() as session:
        clients = await session.api.get_active_clients(stats_level)
        assert len(clients) == 1


@pytest.mark.parametrize("stats_level", STATS_LEVELS)
async def test_sz_ap_stats_accepts_stats_level(create_sz_session, stats_level):
    """SmartZone get_ap_stats accepts StatsLevel/bool like the base."""
    async with create_sz_session() as session:
        aps = await session.api.get_ap_stats(stats_level)
        assert len(aps) == 1


@pytest.mark.parametrize("session_fixture", ["create_r1_session", "create_sz_session"])
async def test_shims_reject_base_ajax_session_helpers(session_fixture, request):
    """Unsupported base helpers raise NotImplementedError, not AssertionError."""
    async with request.getfixturevalue(session_fixture)() as session:
        api = session.api
        with pytest.raises(NotImplementedError):
            await api._cmdstat_noparse("<ajax-request/>")
        with pytest.raises(NotImplementedError):
            await api._conf_noparse("<ajax-request/>")
        with pytest.raises(NotImplementedError):
            await api._get_conf_str(object())
        with pytest.raises(NotImplementedError):
            await api._get_conf(object())


@pytest.mark.parametrize("session_fixture", ["create_r1_session", "create_sz_session"])
async def test_shims_reject_guest_pass_methods(session_fixture, request):
    """Guest-pass methods are unsupported on the shims."""
    async with request.getfixturevalue(session_fixture)() as session:
        api = session.api
        with pytest.raises(NotImplementedError):
            await api.get_guest_passes()
        with pytest.raises(NotImplementedError):
            await api.do_add_guest_passes(ssid="Test")
        with pytest.raises(NotImplementedError):
            await api.do_remove_guest_passes("123456")


@pytest.mark.parametrize("session_fixture", ["create_r1_session", "create_sz_session"])
async def test_shims_get_system_info_and_mesh(session_fixture, request):
    """Shim system/mesh info still resolves through their own sessions."""
    async with request.getfixturevalue(session_fixture)() as session:
        system_info = await session.api.get_system_info()
        assert system_info["sysinfo"]["version"]
        mesh = await session.api.get_mesh_info()
        assert mesh["name"]
