"""Live-network tests for the SmartZone and Ruckus One guest-pass methods.

These tests exercise the guest-pass list/create/remove methods against real
SmartZone and Ruckus One controllers, including a create -> list -> remove
roundtrip. They are marked ``live`` and deselected by default (see
``addopts = "-m 'not live'"`` in ``pyproject.toml``); run them explicitly
with ``pytest -m live``.

Credentials are read from environment variables, one set per provider;
tests are skipped for any provider that isn't configured:

    AIORUCKUS_LIVE_SMARTZONE_HOST / AIORUCKUS_LIVE_SMARTZONE_USERNAME / AIORUCKUS_LIVE_SMARTZONE_PASSWORD
    AIORUCKUS_LIVE_RUCKUSONE_HOST / AIORUCKUS_LIVE_RUCKUSONE_USERNAME / AIORUCKUS_LIVE_RUCKUSONE_PASSWORD

For Ruckus One, ``HOST`` is the full tenant URL (e.g.
``https://asia.ruckus.cloud/<tenant-id>/t/``) and ``USERNAME`` / ``PASSWORD``
are the OAuth2 client id / client secret.

Each roundtrip creates guest passes on a WLAN that accepts them and always
removes them again in a ``finally`` block, so no passes are left behind even
when an assertion fails. WLANs are tried in order until one accepts a guest
pass; if none do, the test is skipped.
"""

from __future__ import annotations

import asyncio
import os
import time
from contextlib import asynccontextmanager

import pytest

from aioruckus.ajaxsession import AjaxSession
from aioruckus.exceptions import BusinessRuleError

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


async def _guest_ssids(api) -> list[str]:
    """Return the SSID (or name) of every WLAN the controller reports."""
    ssids = []
    for wlan in await api.get_wlans():
        ssid = wlan.get("ssid") or wlan.get("name")
        if ssid:
            ssids.append(ssid)
    return ssids


async def _run_roundtrip(api, create):
    """Run ``create(ssid)`` against each WLAN until one accepts guest passes.

    Guest-pass creation only succeeds on guest-enabled WLANs; on other
    WLANs the controller raises ``BusinessRuleError``. Tries every WLAN in
    order and skips the test if none accept guest passes.
    """
    ssids = await _guest_ssids(api)
    if not ssids:
        pytest.skip("no WLANs available for guest-pass creation")
    last_error: Exception | None = None
    for ssid in ssids:
        try:
            await create(ssid)
            return
        except (BusinessRuleError, ValueError) as err:
            last_error = err
    pytest.skip(f"no guest-enabled WLAN found (tried {ssids}): {last_error}")


async def _remove_key(api, key: str) -> None:
    """Remove a guest pass by key, tolerating it already being gone."""
    existing = {g["key"] for g in await api.get_guest_passes()}
    if key in existing:
        await api.do_remove_guest_passes(key)


async def _wait_for_guest_keys(api, keys: set, present: bool = True) -> set:
    """Poll the guest list until all keys are present (or absent).

    Ruckus One creates and deletes guest users asynchronously, so the list
    is eventually consistent; this polls for up to ~10 seconds.
    """
    listed = set()
    for _ in range(10):
        listed = {g["key"] for g in await api.get_guest_passes()}
        if present:
            if keys <= listed:
                return listed
        elif not (keys & listed):
            return listed
        await asyncio.sleep(1)
    return listed


@pytest.mark.asyncio
async def test_shim_guest_pass_batch_roundtrip(live_shim_api):
    """Create, list, and remove a batch of guest passes on the live controller."""
    async with live_shim_api() as api:
        async def create(ssid):
            created = await api.do_add_guest_passes(
                ssid=ssid,
                duration=1,
                duration_unit="day",
                batch_size=2,
                remarks="aioruckus-live-test",
            )
            try:
                assert len(created) == 2
                for guest in created:
                    assert guest.get("key")
                    assert guest.get("id")

                # the new passes appear in the list with their keys
                keys = await _wait_for_guest_keys(
                    api, {g["key"] for g in created}
                )
                assert all(g["key"] in keys for g in created)

                # removal is keyed by the pass key only
                await api.do_remove_guest_passes(*(g["key"] for g in created))
                keys_after = await _wait_for_guest_keys(
                    api, {g["key"] for g in created}, present=False
                )
                assert all(g["key"] not in keys_after for g in created)
            finally:
                for guest in created:
                    await _remove_key(api, guest["key"])

        await _run_roundtrip(api, create)


@pytest.mark.asyncio
async def test_shim_guest_pass_single_roundtrip(live_shim_api):
    """Generate a key and create/remove a single guest pass by key."""
    async with live_shim_api() as api:
        async def create(ssid):
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

                # the new pass appears in the list with its key
                keys = await _wait_for_guest_keys(api, {guest["key"]})
                assert guest["key"] in keys

                # removal is keyed by the pass key only
                await api.do_remove_guest_passes(guest["key"])
                keys_after = await _wait_for_guest_keys(
                    api, {guest["key"]}, present=False
                )
                assert guest["key"] not in keys_after
            finally:
                await _remove_key(api, guest["key"])

        await _run_roundtrip(api, create)


@pytest.mark.asyncio
async def test_shim_guest_pass_custom_key_roundtrip(live_shim_api):
    """A caller-supplied key creates a single pass and round-trips by key."""
    async with live_shim_api() as api:
        async def create(ssid):
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
                assert guest.get("key")
                # Ruckus One never re-exposes the pass key, so it is kept in
                # the "password" field; SmartZone keeps it as the key itself
                pass_key = guest.get("password") or guest["key"]
                assert pass_key.upper() == key.upper()
                assert guest.get("id")

                # the new pass appears in the list with its key
                keys = await _wait_for_guest_keys(api, {guest["key"]})
                assert guest["key"] in keys

                # removal is keyed by the pass key only
                await api.do_remove_guest_passes(guest["key"])
                keys_after = await _wait_for_guest_keys(
                    api, {guest["key"]}, present=False
                )
                assert guest["key"] not in keys_after
            finally:
                await _remove_key(api, guest["key"])

        await _run_roundtrip(api, create)
