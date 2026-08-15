"""Live-network tests for the guest-pass list/create/remove methods.

These tests exercise the guest-pass commands against real ZoneDirector /
Unleashed controllers, including a create -> list -> remove roundtrip.
They are marked ``live`` and deselected by default (see
``addopts = "-m 'not live'"`` in ``pyproject.toml``); run them explicitly
with ``pytest -m live``.

Credentials are read from environment variables, one set per provider;
tests are skipped for any provider that isn't configured:

    AIORUCKUS_LIVE_ZD_HOST / AIORUCKUS_LIVE_ZD_USERNAME / AIORUCKUS_LIVE_ZD_PASSWORD
    AIORUCKUS_LIVE_UNLEASHED_HOST / AIORUCKUS_LIVE_UNLEASHED_USERNAME / AIORUCKUS_LIVE_UNLEASHED_PASSWORD

The plain ``AIORUCKUS_LIVE_HOST`` / ``AIORUCKUS_LIVE_USERNAME`` /
``AIORUCKUS_LIVE_PASSWORD`` variables are still honoured as a fallback for
the ZoneDirector provider.

The roundtrip creates a small batch of guest passes on the first available
WLAN's SSID and always removes them again in a ``finally`` block, so no
passes are left behind even when an assertion fails.
"""

from __future__ import annotations

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
def live_guest_controller(request):
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
def live_guest_api(live_guest_controller):
    """Factory for a live-session async context manager."""
    return lambda: _live_session(live_guest_controller)


async def _first_guest_ssid(api) -> str:
    """Return the SSID of the first guest-enabled WLAN, or '' if none."""
    for wlan in await api.get_wlans():
        if wlan.get("is-guest") == "true":
            ssid = wlan.get("ssid") or wlan.get("name")
            if ssid:
                return ssid
    return ""


@pytest.mark.asyncio
async def test_guest_pass_roundtrip(live_guest_api):
    """Create, list, and remove guest passes by key on the live controller."""
    async with live_guest_api() as api:
        ssid = await _first_guest_ssid(api)
        if not ssid:
            pytest.skip("no guest-enabled WLAN available for guest-pass creation")

        created: list = []
        try:
            created = await api.do_add_guest_passes(
                ssid=ssid,
                duration=1,
                duration_unit="day",
                batch_size=2,
                remarks="aioruckus-live-test",
            )
            assert len(created) == 2
            for guest in created:
                assert guest.get("key")
                assert guest.get("id")
                assert guest.get("ssid") == ssid

            # the new passes appear in the list with their keys
            keys = {g["key"] for g in await api.get_guest_passes()}
            assert all(g["key"] in keys for g in created)

            # removal is keyed by the pass key only
            await api.do_remove_guest_passes(*(g["key"] for g in created))
            keys_after = {g["key"] for g in await api.get_guest_passes()}
            assert all(g["key"] not in keys_after for g in created)
            created = []
        finally:
            # clean up any passes left behind by a failed assertion
            if created:
                existing = {g["key"] for g in await api.get_guest_passes()}
                leftovers = [g["key"] for g in created if g["key"] in existing]
                if leftovers:
                    await api.do_remove_guest_passes(*leftovers)


@pytest.mark.asyncio
async def test_guest_pass_single_roundtrip(live_guest_api):
    """Generate a key and create/remove a single guest pass by key."""
    import time

    async with live_guest_api() as api:
        ssid = await _first_guest_ssid(api)
        if not ssid:
            pytest.skip("no guest-enabled WLAN available for guest-pass creation")

        guest = await api.do_add_guest_pass(
            ssid=ssid,
            name=f"aioruckus-{int(time.time())}",
            duration=1,
            duration_unit="day",
            remarks="aioruckus-live-test",
        )
        try:
            assert guest.get("key")
            assert guest.get("id")
            assert guest.get("ssid") == ssid

            # the new pass appears in the list with its key
            keys = {g["key"] for g in await api.get_guest_passes()}
            assert guest["key"] in keys

            # removal is keyed by the pass key only
            await api.do_remove_guest_passes(guest["key"])
            keys_after = {g["key"] for g in await api.get_guest_passes()}
            assert guest["key"] not in keys_after
        finally:
            # remove the pass if an assertion failed before the removal
            existing = {g["key"] for g in await api.get_guest_passes()}
            if guest["key"] in existing:
                await api.do_remove_guest_passes(guest["key"])


@pytest.mark.asyncio
async def test_guest_pass_custom_key_roundtrip(live_guest_api):
    """A caller-supplied key creates a single pass and is uppercased."""
    import time

    async with live_guest_api() as api:
        ssid = await _first_guest_ssid(api)
        if not ssid:
            pytest.skip("no guest-enabled WLAN available for guest-pass creation")

        key = f"aioruckus{int(time.time()) % 1000000}"
        guest = await api.do_add_guest_pass(
            ssid=ssid,
            name=f"aioruckus-key-{int(time.time())}",
            x_key=key,
            duration=1,
            duration_unit="day",
            remarks="aioruckus-live-test",
        )
        try:
            assert guest.get("key") == key.upper()  # controller uppercases keys
            assert guest.get("id")

            # the new pass appears in the list with its uppercased key
            keys = {g["key"] for g in await api.get_guest_passes()}
            assert guest["key"] in keys

            # removal is keyed by the pass key only
            await api.do_remove_guest_passes(guest["key"])
            keys_after = {g["key"] for g in await api.get_guest_passes()}
            assert guest["key"] not in keys_after
        finally:
            # remove the pass if an assertion failed before the removal
            existing = {g["key"] for g in await api.get_guest_passes()}
            if guest["key"] in existing:
                await api.do_remove_guest_passes(guest["key"])


@pytest.mark.asyncio
async def test_guest_passes_list_shape(live_guest_api):
    """Guest passes list to normalized dicts: key/name/ssid, no x-* leftovers.

    ZoneDirector serves the pass key as ``x-key`` (with a plain ``key``
    duplicate) and guest fields as ``full-name`` / ``wlan``, while Unleashed
    uses ``name`` / ``ssid``; the parser must normalize both to the shared
    ``Guest`` shape.
    """
    async with live_guest_api() as api:
        guests = await api.get_guest_passes()
        assert isinstance(guests, list)
        for guest in guests:
            assert isinstance(guest, dict)
            assert guest.get("key")
            assert "x-key" not in guest          # renamed, not kept
            assert "full-name" not in guest      # renamed to name
            assert "wlan" not in guest           # renamed to ssid
