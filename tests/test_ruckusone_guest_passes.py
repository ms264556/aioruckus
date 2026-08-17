"""Unit tests for the Ruckus One shim guest-pass methods.

The shim maps the shared list/create/remove methods onto the Ruckus One
"Guest User" API: guests are listed via the ``guestUsers/query`` endpoint,
created one at a time via ``wifiNetworks/{id}/guestUsers`` (Ruckus One has
no batch create), optionally re-keyed via a PATCH password update, and
deleted per guest user id. The mock is stateful so the before/after
re-list logic can be exercised.
"""

import json
import re

import pytest

from aioruckus.const import (
    ERROR_GUEST_PASS_BATCH_SIZE,
    ERROR_GUEST_PASS_KEY_INVALID,
    ERROR_INVALID_WLAN,
)

try:
    from .mock_aiohttp import CallbackResult
except ImportError:
    from mock_aiohttp import CallbackResult

pytestmark = pytest.mark.asyncio

R1_HOST = r"^https://api\.(?:eu\.|asia\.)ruckus\.cloud"

DEFAULT_GUESTS = [
    {
        "id": "guest-1",
        "name": "guest-name-1",
        "password": "PASSW0RD1",
        "ssid": "MyWiFi",
        "networkId": "wlan-1",
        "email": "guest1@example.com",
        "mobilePhoneNumber": "+15551234567",
        "notes": "remark",
        "maxDevices": 3,
        "deliveryMethods": ["STUB"],
        "expiration": {"activationType": "Creation", "duration": 1, "unit": "Day"},
        "createdDate": 1760000000000,
        "expirationDate": 1760086400000,
        "guestUserType": "GuestPass",
    },
    {
        "id": "guest-2",
        "name": "guest-name-2",
        "password": "PASSW0RD2",
        "ssid": "MyWiFi",
        "networkId": "wlan-1",
        "email": "",
        "mobilePhoneNumber": "",
        "notes": "sdf",
        "maxDevices": -1,
        "deliveryMethods": ["STUB"],
        "expiration": {"activationType": "Creation", "duration": 2, "unit": "Hour"},
        "createdDate": 1760000000000,
        "expirationDate": 1760007200000,
        "guestUserType": "GuestPass",
    },
]


def _json_response(payload: dict, status: int = 200) -> CallbackResult:
    return CallbackResult(
        body=json.dumps(payload),
        status=status,
        headers={"Content-Type": "application/json"},
    )


def _r1_guest_callback_factory(initial_guests=None):
    """Stateful REST callbacks for the Ruckus One guest-user endpoints.

    Returns one callback per route (list / create / patch / delete) sharing a
    guest store, plus a ``requests`` log of ``(method, path, json)`` tuples.
    """
    store = {g["id"]: dict(g) for g in (initial_guests if initial_guests is not None else DEFAULT_GUESTS)}
    next_id = [100]
    requests = []

    def _guest_from_body(body: dict) -> dict:
        gid = str(next_id[0])
        next_id[0] += 1
        return {
            "id": gid,
            "name": body.get("name", ""),
            "password": f"KEY{gid}",
            "ssid": "MyWiFi",
            "networkId": "wlan-1",
            "email": body.get("email", ""),
            "mobilePhoneNumber": body.get("mobilePhoneNumber", ""),
            "notes": body.get("notes", ""),
            "maxDevices": body.get("maxDevices", 3),
            "deliveryMethods": body.get("deliveryMethods", ["STUB"]),
            "expiration": body.get("expiration"),
            "createdDate": 1760000000000,
            "expirationDate": 1760086400000,
            "guestUserType": "GuestPass",
        }

    def list_cb(url, **kwargs):
        requests.append(("list", url.path, kwargs.get("json") or {}))
        return _json_response({"data": list(store.values()), "totalCount": len(store), "hasMore": False})

    def create_cb(url, **kwargs):
        body = kwargs.get("json") or {}
        requests.append(("create", url.path, body))
        guest = _guest_from_body(body)
        store[guest["id"]] = guest
        return _json_response({"requestId": "create-req", "response": guest}, status=201)

    def patch_cb(url, **kwargs):
        body = kwargs.get("json") or {}
        requests.append(("patch", url.path, body))
        guest_id = url.path.rstrip("/").rsplit("/", 1)[-1]
        if guest_id in store and body.get("password"):
            store[guest_id]["password"] = body["password"]
        return _json_response({"requestId": "patch-req"})

    def delete_cb(url, **kwargs):
        requests.append(("delete", url.path, {}))
        guest_id = url.path.rstrip("/").rsplit("/", 1)[-1]
        store.pop(guest_id, None)
        return CallbackResult(status=204)

    return list_cb, create_cb, patch_cb, delete_cb, requests, store


def _register_r1_guest_routes(aiohttp_context, callbacks):
    """Register the Ruckus One guest-user routes."""
    list_cb, create_cb, patch_cb, delete_cb, _, _ = callbacks
    aiohttp_context.post(
        re.compile(rf"{R1_HOST}/guestUsers/query"),
        callback=list_cb,
    )
    aiohttp_context.post(
        re.compile(rf"{R1_HOST}/wifiNetworks/wlan-1/guestUsers$"),
        callback=create_cb,
    )
    aiohttp_context.patch(
        re.compile(rf"{R1_HOST}/wifiNetworks/wlan-1/guestUsers/"),
        callback=patch_cb,
    )
    aiohttp_context.delete(
        re.compile(rf"{R1_HOST}/wifiNetworks/wlan-1/guestUsers/"),
        callback=delete_cb,
    )


@pytest.mark.asyncio
async def test_r1_get_guest_passes(create_r1_session, aiohttp_context):
    """Guest passes list via guestUsers/query with normalized fields."""
    callbacks = _r1_guest_callback_factory()
    async with create_r1_session() as session:
        _register_r1_guest_routes(aiohttp_context, callbacks)
        guests = await session.api.get_guest_passes()

    assert len(guests) == 2
    first, second = guests
    assert first["key"] == "guest-1"          # R1 keys are the guest user ids
    assert first["password"] == "PASSW0RD1"
    assert first["id"] == "guest-1"
    assert first["name"] == "guest-name-1"
    assert first["ssid"] == "MyWiFi"
    assert first["email"] == "guest1@example.com"
    assert first["phone-number"] == "+15551234567"
    assert first["create-time"] == "1760000000000"
    assert first["expire-time"] == "1760086400000"
    assert first["duration"] == "1"
    assert first["duration-unit"] == "day"
    assert first["shared-guestpass"] == "false"
    assert first["share-number"] == "3"
    assert first["remarks"] == "remark"
    assert first["networkId"] == "wlan-1"
    assert second["key"] == "guest-2"
    assert second["password"] == "PASSW0RD2"
    assert second["shared-guestpass"] == "true"
    assert second["share-number"] == "-1"

    # the list query is a standard paged POST
    assert callbacks[4][0][0] == "list"
    assert callbacks[4][0][1].endswith("/guestUsers/query")
    assert callbacks[4][0][2] == {"page": 1, "pageSize": 100}


@pytest.mark.asyncio
async def test_r1_do_add_guest_passes(create_r1_session, aiohttp_context):
    """A batch create makes one guest user per pass and returns the new ones."""
    callbacks = _r1_guest_callback_factory()
    async with create_r1_session() as session:
        _register_r1_guest_routes(aiohttp_context, callbacks)
        created = await session.api.do_add_guest_passes(
            ssid="MyWiFi",
            duration=1,
            duration_unit="day",
            batch_size=2,
            remarks="aioruckus-test",
        )

    assert len(created) == 2
    assert all(g["id"] not in ("guest-1", "guest-2") for g in created)
    assert all(g["key"] for g in created)
    assert all(g["ssid"] == "MyWiFi" for g in created)
    assert all(g["remarks"] == "aioruckus-test" for g in created)

    creates = [r for r in callbacks[4] if r[0] == "create"]
    assert len(creates) == 2
    for _, path, body in creates:
        assert path.endswith("/wifiNetworks/wlan-1/guestUsers")
        assert body["name"].startswith("batch-")
        assert body["deliveryMethods"] == ["STUB"]
        assert body["expiration"] == {"activationType": "Creation", "duration": 1, "unit": "Day"}
        assert body["maxDevices"] == 1
        assert body["notes"] == "aioruckus-test"
        assert body["mobilePhoneNumber"] == ""
    assert creates[0][2]["name"] != creates[1][2]["name"]


@pytest.mark.asyncio
async def test_r1_do_add_guest_passes_batch_size_validation(create_r1_session, aiohttp_context):
    """Batch size outside 2..100 raises ValueError without any create."""
    callbacks = _r1_guest_callback_factory()
    async with create_r1_session() as session:
        _register_r1_guest_routes(aiohttp_context, callbacks)
        with pytest.raises(ValueError, match=ERROR_GUEST_PASS_BATCH_SIZE):
            await session.api.do_add_guest_passes(ssid="MyWiFi", batch_size=1)

    assert not [r for r in callbacks[4] if r[0] == "create"]


@pytest.mark.asyncio
async def test_r1_do_add_guest_passes_invalid_ssid(create_r1_session, aiohttp_context):
    """An unknown SSID raises ValueError without creating anything."""
    callbacks = _r1_guest_callback_factory()
    async with create_r1_session() as session:
        _register_r1_guest_routes(aiohttp_context, callbacks)
        with pytest.raises(ValueError, match=ERROR_INVALID_WLAN):
            await session.api.do_add_guest_passes(ssid="NoSuchWiFi", batch_size=2)

    assert not [r for r in callbacks[4] if r[0] == "create"]


@pytest.mark.asyncio
async def test_r1_do_add_guest_pass(create_r1_session, aiohttp_context):
    """A single guest pass is created with an auto-generated key."""
    callbacks = _r1_guest_callback_factory()
    async with create_r1_session() as session:
        _register_r1_guest_routes(aiohttp_context, callbacks)
        guest = await session.api.do_add_guest_pass(
            ssid="MyWiFi",
            name="single-guest",
            duration=1,
            duration_unit="day",
            remarks="aioruckus-test",
        )

    assert guest["key"]
    assert guest["id"]
    assert guest["name"] == "single-guest"
    assert guest["ssid"] == "MyWiFi"
    assert guest["remarks"] == "aioruckus-test"

    creates = [r for r in callbacks[4] if r[0] == "create"]
    assert len(creates) == 1
    _, path, body = creates[0]
    assert path.endswith("/wifiNetworks/wlan-1/guestUsers")
    assert body["name"] == "single-guest"
    assert body["deliveryMethods"] == ["STUB"]
    assert not [r for r in callbacks[4] if r[0] == "patch"]  # no re-key


@pytest.mark.asyncio
async def test_r1_do_add_guest_pass_custom_key(create_r1_session, aiohttp_context):
    """A caller-supplied key is validated and applied via a PATCH password."""
    callbacks = _r1_guest_callback_factory()
    async with create_r1_session() as session:
        _register_r1_guest_routes(aiohttp_context, callbacks)
        guest = await session.api.do_add_guest_pass(
            ssid="MyWiFi",
            name="custom-key-guest",
            x_key="mykey123",
            duration=1,
            duration_unit="day",
        )

    assert guest["key"] == "100"              # R1 keys are the guest user ids
    assert guest["password"] == "mykey123"

    patches = [r for r in callbacks[4] if r[0] == "patch"]
    assert len(patches) == 1
    _, path, body = patches[0]
    assert path.endswith("/wifiNetworks/wlan-1/guestUsers/100")
    assert body == {"password": "mykey123"}


@pytest.mark.asyncio
async def test_r1_do_add_guest_pass_invalid_key(create_r1_session, aiohttp_context):
    """An invalid caller-supplied key raises ValueError before any request."""
    callbacks = _r1_guest_callback_factory()
    async with create_r1_session() as session:
        _register_r1_guest_routes(aiohttp_context, callbacks)
        with pytest.raises(ValueError, match=re.escape(ERROR_GUEST_PASS_KEY_INVALID)):
            await session.api.do_add_guest_pass(ssid="MyWiFi", x_key="bad key!")

    assert not [r for r in callbacks[4] if r[0] == "create"]


@pytest.mark.asyncio
async def test_r1_do_remove_guest_passes(create_r1_session, aiohttp_context):
    """Removal resolves guest user ids to deletes, one per guest."""
    callbacks = _r1_guest_callback_factory()
    async with create_r1_session() as session:
        _register_r1_guest_routes(aiohttp_context, callbacks)
        await session.api.do_remove_guest_passes("guest-1", "guest-2")

    deletes = [r for r in callbacks[4] if r[0] == "delete"]
    assert len(deletes) == 2
    assert {path for _, path, _ in deletes} == {
        "/wifiNetworks/wlan-1/guestUsers/guest-1",
        "/wifiNetworks/wlan-1/guestUsers/guest-2",
    }

    # the guests are gone from the store
    assert store_ids(callbacks) == set()


def store_ids(callbacks) -> set:
    """Return the ids currently in the callback guest store."""
    return {g["id"] for g in callbacks[5].values()}


@pytest.mark.asyncio
async def test_r1_do_remove_guest_passes_unknown_key(create_r1_session, aiohttp_context):
    """Removal of an unknown key raises ValueError without deleting anything."""
    callbacks = _r1_guest_callback_factory()
    async with create_r1_session() as session:
        _register_r1_guest_routes(aiohttp_context, callbacks)
        with pytest.raises(ValueError, match="not found"):
            await session.api.do_remove_guest_passes("NOPE")

    assert not [r for r in callbacks[4] if r[0] == "delete"]


@pytest.mark.asyncio
async def test_r1_do_remove_guest_passes_no_keys(create_r1_session, aiohttp_context):
    """Removal with no keys is a no-op."""
    callbacks = _r1_guest_callback_factory()
    async with create_r1_session() as session:
        _register_r1_guest_routes(aiohttp_context, callbacks)
        await session.api.do_remove_guest_passes()

    assert not [r for r in callbacks[4] if r[0] == "delete"]
