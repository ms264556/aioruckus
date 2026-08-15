"""Unit tests for the stats_level parameter on the AJAX stats methods."""

import pytest

from aioruckus.const import StatsLevel


@pytest.mark.asyncio
async def test_active_clients_default_is_level_1(create_ajax_session, set_ajax_results):
    """Bare call requests LEVEL='1' (basic) client stats."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        clients = await session.api.get_active_clients()
        assert len(clients) == 1
        assert "avg-rssi" not in clients[0]
        assert "interval-stats" not in clients[0]


@pytest.mark.asyncio
async def test_active_clients_level_1_explicit(create_ajax_session, set_ajax_results):
    """Explicit StatsLevel.L1 requests LEVEL='1' (basic) client stats."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        clients = await session.api.get_active_clients(StatsLevel.L1)
        assert len(clients) == 1
        assert "avg-rssi" not in clients[0]
        assert "interval-stats" not in clients[0]


@pytest.mark.asyncio
async def test_active_clients_level_2(create_ajax_session, set_ajax_results):
    """Level 2 adds extended client stats (e.g. avg-rssi)."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        clients = await session.api.get_active_clients(StatsLevel.L2)
        assert len(clients) == 1
        assert clients[0]["avg-rssi"] == "-50"
        assert "interval-stats" not in clients[0]


@pytest.mark.asyncio
async def test_active_clients_level_3(create_ajax_session, set_ajax_results):
    """Level 3 requests 24h interval stats and returns them."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        clients = await session.api.get_active_clients(StatsLevel.L3)
        assert len(clients) == 1
        assert "interval-stats" in clients[0]


@pytest.mark.asyncio
async def test_active_clients_interval_stats_true(create_ajax_session, set_ajax_results):
    """Legacy boolean True requests interval stats (L3)."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        clients = await session.api.get_active_clients(True)
        assert len(clients) == 1
        assert "interval-stats" in clients[0]


@pytest.mark.asyncio
async def test_active_clients_interval_stats_false(create_ajax_session, set_ajax_results):
    """Legacy boolean False requests basic stats (L1)."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        clients = await session.api.get_active_clients(False)
        assert len(clients) == 1
        assert "avg-rssi" not in clients[0]
        assert "interval-stats" not in clients[0]


@pytest.mark.asyncio
async def test_ap_stats_default_is_level_1(create_ajax_session, set_ajax_results):
    """Bare call requests LEVEL='1' (basic) AP stats."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        aps = await session.api.get_ap_stats()
        assert len(aps) == 1
        assert "vap" not in aps[0]
        assert "interval-stats" not in aps[0]


@pytest.mark.asyncio
async def test_ap_stats_level_1_explicit(create_ajax_session, set_ajax_results):
    """Explicit StatsLevel.L1 requests LEVEL='1' (basic) AP stats."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        aps = await session.api.get_ap_stats(StatsLevel.L1)
        assert len(aps) == 1
        assert "vap" not in aps[0]
        assert "interval-stats" not in aps[0]


@pytest.mark.asyncio
async def test_ap_stats_level_2(create_ajax_session, set_ajax_results):
    """Level 2 adds VAP info to AP stats."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        aps = await session.api.get_ap_stats(StatsLevel.L2)
        assert len(aps) == 1
        assert "vap" in aps[0]
        assert "interval-stats" not in aps[0]


@pytest.mark.asyncio
async def test_ap_stats_level_3(create_ajax_session, set_ajax_results):
    """Level 3 requests AP interval stats and returns them."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        aps = await session.api.get_ap_stats(StatsLevel.L3)
        assert len(aps) == 1
        assert "interval-stats" in aps[0]


@pytest.mark.asyncio
async def test_ap_stats_interval_stats_true(create_ajax_session, set_ajax_results):
    """Legacy boolean True requests interval stats (L3)."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        aps = await session.api.get_ap_stats(True)
        assert len(aps) == 1
        assert "interval-stats" in aps[0]


@pytest.mark.asyncio
async def test_ap_stats_interval_stats_false(create_ajax_session, set_ajax_results):
    """Legacy boolean False requests basic stats (L1)."""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        aps = await session.api.get_ap_stats(False)
        assert len(aps) == 1
        assert "vap" not in aps[0]
        assert "interval-stats" not in aps[0]
