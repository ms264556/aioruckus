"""Unit tests for the guest-pass list/create/remove API methods.

The methods use the same JSP-form algorithms on ZoneDirector and Unleashed:
passes are listed via a ``getconf`` guest-list request, created via
``mon_guestdata.jsp`` (key generation) / ``mon_createguest.jsp`` (create)
form POSTs, and removed via a ``delobj`` on ``guest-list``. The mock is
stateful so the before/after re-list logic can be exercised.
"""

import json
import re
import time

import pytest

from aioruckus.const import ERROR_GUEST_PASS_BATCH_SIZE, ERROR_GUEST_PASS_KEY_INVALID

try:
    from .mock_aiohttp import CallbackResult
except ImportError:
    from mock_aiohttp import CallbackResult

pytestmark = pytest.mark.asyncio

DEFAULT_GUESTS = [
    {"x-key": "157971", "id": "1", "name": "TestGuestname", "ssid": "VoucherTesting",
     "shared-guestpass": "true", "create-time": "1786771671",
     "expire-time": "1787376471", "remarks": "test remark"},
    {"x-key": "544039", "id": "5", "name": "Guest-5", "ssid": "VoucherTesting",
     "shared-guestpass": "true", "create-time": "1786772530",
     "expire-time": "1787377330", "remarks": "sdf"},
]


def _guest_xml(guest: dict) -> str:
    attrs = " ".join(f'{k}="{v}"' for k, v in guest.items())
    return f"<guest {attrs} />"


def _ajax_response(content: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE ajax-response>'
        f'<ajax-response><response type="object" id="guest-list.1">{content}</response>'
        "</ajax-response>\n"
    )


def _guest_callback_factory(initial_guests=None, keygen_xml=None, create_error=None):
    """Stateful conf/form callback for guest requests.

    Serves the getconf guest-list, ``mon_guestdata.jsp`` (key generation),
    ``mon_createguest.jsp`` (create) and ``delobj`` requests, recording
    ``(url, data)`` tuples. The guest store is mutated by creates and
    delobj so the before/after re-list logic works.

    Args:
        initial_guests: guests present in the store at start.
        keygen_xml: JSON returned by ``mon_guestdata.jsp``.
        create_error: JSON returned by ``mon_createguest.jsp`` instead of
            a success response (to exercise error handling).
    """
    store = {g["x-key"]: dict(g) for g in (initial_guests if initial_guests is not None else DEFAULT_GUESTS)}
    next_id = [10]
    requests = []

    def render() -> str:
        return _ajax_response(
            "<resultset>" + "".join(_guest_xml(g) for g in store.values()) + "</resultset>"
        )

    def callback(url, **kwargs):
        url_str = str(url)
        data = kwargs.get("data")
        requests.append((url_str, data))
        if "mon_guestdata.jsp" in url_str:
            return CallbackResult(body=keygen_xml if keygen_xml is not None
                                  else '{"wlanName":"VoucherTesting","key":"136497"}')
        if "mon_createguest.jsp" in url_str:
            if create_error is not None:
                return CallbackResult(body=create_error)
            form = data if isinstance(data, dict) else {}
            if form.get("gentype") == "multiple":
                keys = [f"new{next_id[0]}", f"new{next_id[0] + 1}"]
                for i, key in enumerate(keys):
                    store[key] = {"x-key": key, "id": str(next_id[0] + i),
                                  "name": f"Guest-{next_id[0] + i}",
                                  "ssid": form.get("guest-wlan", ""),
                                  "create-time": str(int(time.time()))}
                next_id[0] += 2
                body = json.dumps({"result": "OK", "key": keys[0], "ids": "2"})
            else:
                key = form.get("key") or "136497"
                store[key] = {"x-key": key, "id": str(next_id[0]),
                              "name": form.get("fullname", ""),
                              "ssid": form.get("guest-wlan", ""),
                              "create-time": str(int(time.time()))}
                next_id[0] += 1
                body = json.dumps({"result": "DONE", "key": key,
                                   "fullname": form.get("fullname", ""),
                                   "wlan": form.get("guest-wlan", "")})
            return CallbackResult(body=body)
        if isinstance(data, str) and "delobj" in data:
            for guest_id in re.findall(r"<guest id='([^']+)'", data):
                for key, guest in list(store.items()):
                    if guest["id"] == guest_id:
                        del store[key]
            return CallbackResult(body=_ajax_response(""))
        if isinstance(data, str) and "guest-list" in data:
            return CallbackResult(body=render())
        return CallbackResult(body="\n")

    return callback, requests, store


def _register_guest_callback(aiohttp_context, callback):
    """Register the guest callback, overriding the default session callback."""
    aiohttp_context.post(
        re.compile(r"_(?:conf|cmdstat)\.jsp|mon_guestdata\.jsp|mon_createguest\.jsp"),
        callback=callback,
    )


@pytest.mark.asyncio
async def test_get_guest_passes(create_ajax_session, aiohttp_context):
    """Guest passes list via getconf with the pass key renamed to key."""
    callback, requests, _ = _guest_callback_factory()
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        guests = await session.api.get_guest_passes()

    assert len(guests) == 2
    first, second = guests
    assert first["key"] == "157971"
    assert "x-key" not in first                  # renamed like other x-* attributes
    assert first["name"] == "TestGuestname"
    assert first["ssid"] == "VoucherTesting"
    assert first["expire-time"] == "1787376471"
    assert first["shared-guestpass"] == "true"
    assert second["key"] == "544039"
    assert second["id"] == "5"

    _, data = requests[0]
    assert data.startswith("<ajax-request action='getconf'")
    assert "comp='guest-list'" in data
    assert "<guest self-service='!true'/>" in data


@pytest.mark.asyncio
async def test_get_guest_passes_single(create_ajax_session, aiohttp_context):
    """A single guest pass still parses to a list of one."""
    callback, requests, _ = _guest_callback_factory(initial_guests=[DEFAULT_GUESTS[0]])
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        guests = await session.api.get_guest_passes()

    assert isinstance(guests, list)
    assert len(guests) == 1
    assert guests[0]["key"] == "157971"


@pytest.mark.asyncio
async def test_get_guest_passes_empty(create_ajax_session, aiohttp_context):
    """An empty guest list parses to []."""
    callback, requests, _ = _guest_callback_factory(initial_guests=[])
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        guests = await session.api.get_guest_passes()

    assert guests == []


# ---------------------------------------------------------------------------
# Real controller XML shapes (captured from live ZD1200 / Unleashed 200.19)
# ---------------------------------------------------------------------------

_WRAP = (
    '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE ajax-response>'
    '<ajax-response><response type="object" id="guest-list.1">'
    "<resultset>{}</resultset></response></ajax-response>"
)


def _parse_shape(guest_xml: str) -> dict:
    """Parse a single live-captured guest element via _parse_guest_list."""
    from aioruckus.ruckusajaxapi import _parse_guest_list

    guests = _parse_guest_list(_WRAP.format(guest_xml))
    assert len(guests) == 1
    return guests[0]


async def test_parse_unleashed_shape():
    """Unleashed serves name/ssid + x-key; key is renamed, no leftovers."""
    guest = _parse_shape(
        '<guest shared-guestpass="true" share-number="2" created-by="tony" '
        'role-id="2147483647" countdown-by-issued="false" '
        'create-time="1786771671" valid-time="61200" start-time="" '
        'expire-time="1787376471" email="guesttest@tonyrielly.com" '
        'phone-number="12345678" reauth-interval-unit="min" '
        'remarks="test remark" name="TestGuestname" x-key="157971" '
        'id="1" ssid="VoucherTesting" reauth-enabled="false" />'
    )
    assert guest["key"] == "157971"
    assert guest["name"] == "TestGuestname"
    assert guest["ssid"] == "VoucherTesting"
    assert guest["id"] == "1"
    assert "x-key" not in guest
    assert "full-name" not in guest
    assert "wlan" not in guest


async def test_parse_zd_shape():
    """ZD serves full-name/wlan + x-key plus a plain key duplicate."""
    guest = _parse_shape(
        '<guest full-name="Test Pass Name" wlan="TestGuestPasses" '
        'x-key="BVCIS-TBYBD" id="1" key="BVCIS-TBYBD" '
        'create-time="1786788715" />'
    )
    assert guest["key"] == "BVCIS-TBYBD"
    assert guest["name"] == "Test Pass Name"
    assert guest["ssid"] == "TestGuestPasses"
    assert guest["id"] == "1"
    assert "x-key" not in guest          # renamed, not kept
    assert "full-name" not in guest      # renamed to name
    assert "wlan" not in guest           # renamed to ssid


async def test_parse_both_name_and_full_name():
    """Controllers that emit both name and full-name keep the plain name."""
    guest = _parse_shape(
        '<guest name="TestGuestname" full-name="TestGuestname" '
        'ssid="VoucherTesting" x-key="157971" id="1" '
        'create-time="1786771671" />'
    )
    assert guest["key"] == "157971"
    assert guest["name"] == "TestGuestname"
    assert guest["ssid"] == "VoucherTesting"
    assert "full-name" not in guest      # redundant duplicate dropped


@pytest.mark.asyncio
async def test_do_add_guest_passes(create_ajax_session, aiohttp_context):
    """Batch create posts the multiple form and returns the new passes."""
    callback, requests, _ = _guest_callback_factory()
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        guests = await session.api.do_add_guest_passes(
            ssid="VoucherTesting",
            duration=72,
            duration_unit="day",
            batch_size=2,
            remarks="sdf",
            shared=True,
            share_number=2,
        )

    assert [g["key"] for g in guests] == ["new10", "new11"]
    assert all(g["id"] for g in guests)
    assert all(g["ssid"] == "VoucherTesting" for g in guests)

    assert len(requests) == 3  # before-list, create form, after-list
    assert "guest-list" in requests[0][1]
    form_url, form = requests[1]
    assert "mon_createguest.jsp" in form_url
    assert form["gentype"] == "multiple"
    assert form["createToNum"] == "2"
    assert form["batchpass"] == ""
    assert form["guest-wlan"] == "VoucherTesting"
    assert form["duration"] == "72"
    assert form["duration-unit"] == "day"
    assert form["remarks"] == "sdf"
    assert form["shared"] == "true"


@pytest.mark.asyncio
async def test_do_add_guest_passes_batch_size_validation(create_ajax_session, aiohttp_context):
    """Batch sizes outside 2..100 are rejected before any request is sent."""
    callback, requests, _ = _guest_callback_factory()
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        with pytest.raises(ValueError, match=ERROR_GUEST_PASS_BATCH_SIZE):
            await session.api.do_add_guest_passes(ssid="VoucherTesting", batch_size=1)
        with pytest.raises(ValueError, match=ERROR_GUEST_PASS_BATCH_SIZE):
            await session.api.do_add_guest_passes(ssid="VoucherTesting", batch_size=101)

    assert requests == []


@pytest.mark.asyncio
async def test_do_add_guest_passes_error(create_ajax_session, aiohttp_context):
    """A mon_createguest.jsp failure is raised with the controller message."""
    error = json.dumps({"result": "E_Fail", "errorMsg": "guest pass creation failed"})
    callback, requests, _ = _guest_callback_factory(create_error=error)
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        with pytest.raises(ValueError, match="guest pass creation failed"):
            await session.api.do_add_guest_passes(ssid="VoucherTesting")


@pytest.mark.asyncio
async def test_do_add_guest_pass(create_ajax_session, aiohttp_context):
    """A single pass: generate a key, create it, and complete it from the list."""
    callback, requests, _ = _guest_callback_factory()
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        guest = await session.api.do_add_guest_pass(
            ssid="VoucherTesting",
            name="TestGuestname",
            duration=17,
            duration_unit="hour",
            remarks="test remark",
            shared=True,
            share_number=2,
            email="guesttest@tonyrielly.com",
            phone_number="12345678",
        )

    assert len(requests) == 3  # key gen, create form, completion re-list
    key_url, _ = requests[0]
    assert "mon_guestdata.jsp" in key_url
    form_url, form = requests[1]
    assert "mon_createguest.jsp" in form_url
    assert form["gentype"] == "single"
    assert form["key"] == "136497"          # the generated key is reused
    assert form["fullname"] == "TestGuestname"
    assert form["guest-wlan"] == "VoucherTesting"
    assert form["duration"] == "17"
    assert form["duration-unit"] == "hour"

    assert guest["key"] == "136497"
    assert guest["id"] == "10"              # completed from the re-list
    assert guest["name"] == "TestGuestname"
    assert guest["ssid"] == "VoucherTesting"


@pytest.mark.asyncio
async def test_do_add_guest_pass_generate_error(create_ajax_session, aiohttp_context):
    """A key-generation failure raises before any create is attempted."""
    callback, requests, _ = _guest_callback_factory(keygen_xml="{}")
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        with pytest.raises(ValueError):
            await session.api.do_add_guest_pass(ssid="VoucherTesting")

    assert len(requests) == 1  # only the key request, no create attempted


@pytest.mark.asyncio
async def test_do_add_guest_pass_create_error(create_ajax_session, aiohttp_context):
    """A create-guest failure (e.g. duplicate pass name) is raised."""
    error = json.dumps({"result": "E_DuplicatedValue", "errorMsg": "name already exists"})
    callback, requests, _ = _guest_callback_factory(create_error=error)
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        with pytest.raises(ValueError, match="already exists"):
            await session.api.do_add_guest_pass(ssid="VoucherTesting", name="TestGuestname")

    assert len(requests) == 2  # key generated, then create failed


@pytest.mark.asyncio
async def test_do_add_guest_pass_custom_key(create_ajax_session, aiohttp_context):
    """A caller-supplied key skips key generation and is uppercased."""
    callback, requests, _ = _guest_callback_factory()
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        guest = await session.api.do_add_guest_pass(
            ssid="VoucherTesting", name="TestGuestname", x_key="Abc123"
        )

    assert len(requests) == 2  # create form + completion re-list, no key gen
    form_url, form = requests[0]
    assert "mon_guestdata.jsp" not in form_url
    assert "mon_createguest.jsp" in form_url
    assert form["key"] == "ABC123"          # uppercased like the controller does
    assert guest["key"] == "ABC123"
    assert guest["id"] == "10"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_key",
    [
        "a",  # too short
        "abcdefghijklmnopq",  # too long
        "ab cd",
        "ab#cd",
        "ab&cd",
        "ab+cd",
        'ab"cd',
        "ab'cd",
        "ab,cd",
        "ab<cd",
        "ab>cd",
    ],
)
async def test_do_add_guest_pass_invalid_key(create_ajax_session, aiohttp_context, bad_key):
    """Invalid guest keys are rejected before any request is sent."""
    callback, requests, _ = _guest_callback_factory()
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        with pytest.raises(ValueError) as excinfo:
            await session.api.do_add_guest_pass(ssid="VoucherTesting", x_key=bad_key)

    assert str(excinfo.value) == ERROR_GUEST_PASS_KEY_INVALID
    assert requests == []


@pytest.mark.asyncio
async def test_do_remove_guest_passes(create_ajax_session, aiohttp_context):
    """Removal resolves keys to ids via the list, then deletes by id."""
    callback, requests, store = _guest_callback_factory()
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        await session.api.do_remove_guest_passes("157971", "544039")

    assert len(requests) == 2
    _, list_data = requests[0]
    assert "getconf" in list_data
    assert "guest-list" in list_data
    _, del_data = requests[1]
    assert "delobj" in del_data
    assert "<guest id='1'></guest>" in del_data
    assert "<guest id='5'></guest>" in del_data
    assert "157971" not in del_data
    assert store == {}


@pytest.mark.asyncio
async def test_do_remove_guest_passes_unknown_key(create_ajax_session, aiohttp_context):
    """Removing a key that is not in the list raises ValueError."""
    callback, requests, _ = _guest_callback_factory()
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        with pytest.raises(ValueError, match="999999"):
            await session.api.do_remove_guest_passes("999999")

    assert len(requests) == 1  # only the list lookup, no delete attempted


@pytest.mark.asyncio
async def test_do_remove_guest_passes_no_keys(create_ajax_session, aiohttp_context):
    """Removing with no keys is a no-op."""
    callback, requests, _ = _guest_callback_factory()
    async with create_ajax_session() as session:
        _register_guest_callback(aiohttp_context, callback)
        await session.api.do_remove_guest_passes()

    assert requests == []
