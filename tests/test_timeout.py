"""Session request methods must treat a None timeout as "don't override".

Passing ``timeout=None`` explicitly to aiohttp means "no timeout at all"
(``ClientTimeout(total=None)``), which silently defeats the timeout configured
on the ``ClientSession``. A ``None`` per-call timeout therefore has to be
omitted from the request kwargs entirely, so aiohttp falls back to the
session's own timeout. These tests inspect the kwargs the session actually
hands to aiohttp.

The stats methods sit on top of that plumbing, so they get the same treatment:
an explicit timeout has to reach aiohttp, and no timeout at all has to leave
the session's own timeout in charge.
"""

from __future__ import annotations

import json
import re

import aiohttp
import pytest
from multidict import CIMultiDict, CIMultiDictProxy

from aioruckus.const import StatsLevel
from aioruckus.ruckusonesession import RuckusOneSession
from aioruckus.smartzonesession import SmartZoneSession
from aioruckus.unleashedsession import UnleashedSession

from .mock_aiohttp import CallbackResult

pytestmark = pytest.mark.asyncio


@pytest.fixture
def recorded_requests(aiohttp_context, monkeypatch):
    calls = []
    match = aiohttp_context.match

    def _record(method, url, **kwargs):
        calls.append(kwargs)
        return match(method, url, **kwargs)

    monkeypatch.setattr(aiohttp_context, "match", _record)
    return calls


class _RecordingResponse:
    """Minimal stand-in for aiohttp.ClientResponse that records request kwargs."""

    def __init__(self, recorded: list[dict], body: str = "<ajax-response/>"):
        self._recorded = recorded
        self._body = body
        self.status = 200
        self.content_type = "text/plain"
        self.headers = CIMultiDictProxy(CIMultiDict())
        self.url = "https://example.invalid/"

    async def text(self, *args, **kwargs) -> str:
        return self._body

    async def json(self, *args, **kwargs):
        return {}

    async def read(self) -> bytes:
        return self._body.encode()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> None:
        return None


class _RecordingSession:
    """Drop-in for aiohttp.ClientSession recording each request's kwargs."""

    def __init__(self):
        self.calls: list[dict] = []
        self.headers: dict = {}

    def __call(self, **kwargs):
        self.calls.append(kwargs)
        return _RecordingResponse(self.calls)

    def post(self, *args, **kwargs):
        return self.__call(**kwargs)

    def get(self, *args, **kwargs):
        return self.__call(**kwargs)

    def delete(self, *args, **kwargs):
        return self.__call(**kwargs)

    async def close(self) -> None:
        pass


async def test_unleashed_ajax_request_omits_timeout_when_none():
    """A None timeout is not forwarded, so the ClientSession timeout applies."""
    client = _RecordingSession()
    session = UnleashedSession("host", "user", "pass", client)
    session.base_url = aiohttp.client.URL("https://host/admin/")

    await session._ajax_request("_cmdstat.jsp", "<ajax-request/>")

    assert client.calls, "request was not issued"
    assert "timeout" not in client.calls[-1]


async def test_unleashed_ajax_request_forwards_int_timeout():
    """An explicit int timeout is still honoured."""
    client = _RecordingSession()
    session = UnleashedSession("host", "user", "pass", client)
    session.base_url = aiohttp.client.URL("https://host/admin/")

    await session._ajax_request("_cmdstat.jsp", "<ajax-request/>", timeout=7)

    assert client.calls[-1]["timeout"] == aiohttp.ClientTimeout(total=7)


async def test_unleashed_request_file_omits_timeout_when_none():
    """File downloads also skip the timeout kwarg when None."""
    client = _RecordingSession()
    session = UnleashedSession("host", "user", "pass", client)
    session.base_url = aiohttp.client.URL("https://host/admin/")

    await session._request_file("backup.tar")

    assert "timeout" not in client.calls[-1]


async def test_smartzone_request_omits_timeout_when_none():
    """SmartZone request() skips the timeout kwarg when None."""
    client = _RecordingSession()
    session = SmartZoneSession("host", "user", "pass", client)
    session._SmartZoneSession__base_url = aiohttp.client.URL("https://host/wsg/api/public/v9_0")
    session._SmartZoneSession__service_ticket = "ticket"

    await session._request("get", "session", timeout=None)

    assert "timeout" not in client.calls[-1]


async def test_ruckusone_request_omits_timeout_when_none():
    """Ruckus One request() skips the timeout kwarg when None."""
    client = _RecordingSession()
    session = RuckusOneSession("host", "user", "pass", client)
    session._RuckusOneSession__base_url = aiohttp.client.URL("https://api.ruckus.cloud")
    session._RuckusOneSession__bearer_token = "Bearer token"

    await session._request("get", "tenants/self", timeout=None)

    assert "timeout" not in client.calls[-1]


async def test_get_system_info_forwards_timeout(create_ajax_session, record_ajax_requests):
    """get_system_info() hands its timeout to aiohttp."""
    async with create_ajax_session() as session:
        calls = record_ajax_requests()
        await session.api.get_system_info(timeout=7)

    assert calls[-1]["timeout"] == aiohttp.ClientTimeout(total=7)


@pytest.mark.parametrize(
    "method_name",
    [
        "get_ap_group_stats",
        "get_wlan_group_stats",
        "get_dpsk_stats",
        "get_inactive_clients",
        "get_aps",
        "get_acls",
        "get_mesh_info",
        "get_zerotouch_mesh_ap_serials",
    ],
)
async def test_stats_and_list_getters_forward_timeout(
    create_ajax_session, record_ajax_requests, method_name
):
    """The remaining stats/list getters hand their timeout to aiohttp.

    The shared mock does not answer every endpoint these methods use, so some
    raise once the response fails to parse. The request is issued before that
    happens, which is what this test asserts on.
    """
    async with create_ajax_session() as session:
        calls = record_ajax_requests()
        try:
            await getattr(session.api, method_name)(timeout=7)
        except RuntimeError:
            # "The command was not understood": the mock has no payload for
            # this endpoint, so the request went out and the parse failed.
            pass

    assert calls, f"{method_name} issued no request"
    assert all(
        call["timeout"] == aiohttp.ClientTimeout(total=7) for call in calls
    ), f"{method_name} dropped the timeout on at least one request"


async def test_get_ap_stats_forwards_timeout(create_ajax_session, record_ajax_requests):
    """get_ap_stats() hands its timeout to aiohttp."""
    async with create_ajax_session() as session:
        calls = record_ajax_requests()
        await session.api.get_ap_stats(timeout=7)

    assert calls[-1]["timeout"] == aiohttp.ClientTimeout(total=7)


async def test_get_active_clients_forwards_timeout(create_ajax_session, record_ajax_requests):
    """get_active_clients() hands its timeout to aiohttp."""
    async with create_ajax_session() as session:
        calls = record_ajax_requests()
        await session.api.get_active_clients(timeout=7)

    assert calls[-1]["timeout"] == aiohttp.ClientTimeout(total=7)


async def test_get_vap_stats_forwards_timeout(create_ajax_session, record_ajax_requests):
    """get_vap_stats() hands its timeout to aiohttp."""
    async with create_ajax_session() as session:
        calls = record_ajax_requests()
        await session.api.get_vap_stats(timeout=7)

    assert calls[-1]["timeout"] == aiohttp.ClientTimeout(total=7)


async def test_level_3_stats_forward_timeout_to_every_request(
    create_ajax_session, record_ajax_requests
):
    """Level 3 needs a timestamp first, so both requests carry the timeout."""
    async with create_ajax_session() as session:
        calls = record_ajax_requests()
        await session.api.get_ap_stats(StatsLevel.L3, timeout=7)

    assert len(calls) == 2, "expected a timestamp request followed by a stats request"
    assert all(call["timeout"] == aiohttp.ClientTimeout(total=7) for call in calls)


async def test_stats_methods_omit_timeout_by_default(create_ajax_session, record_ajax_requests):
    """Without a timeout the session's own timeout stays in charge."""
    async with create_ajax_session() as session:
        calls = record_ajax_requests()
        await session.api.get_system_info()
        await session.api.get_ap_stats()
        await session.api.get_active_clients()
        await session.api.get_vap_stats()

    assert calls, "no requests were recorded"
    assert not any("timeout" in call for call in calls)


@pytest.mark.parametrize(
    "timeout_kwargs, expected",
    [
        ({}, "absent"),
        ({"timeout": None}, "absent"),
        ({"timeout": 7}, aiohttp.ClientTimeout(total=7)),
        ({"timeout": 30}, aiohttp.ClientTimeout(total=30)),
    ],
)
@pytest.mark.parametrize(
    "session_fixture, method_name",
    [
        ("create_r1_session", "get_system_info"),
        ("create_r1_session", "get_active_clients"),
        ("create_r1_session", "get_ap_stats"),
        ("create_r1_session", "get_aps"),
        ("create_r1_session", "get_wlans"),
        ("create_r1_session", "get_mesh_info"),
        ("create_sz_session", "get_active_clients"),
        ("create_sz_session", "get_inactive_clients"),
        ("create_sz_session", "get_ap_stats"),
        ("create_sz_session", "get_aps"),
        ("create_sz_session", "get_wlans"),
    ],
)
async def test_shim_methods_forward_timeout(
    session_fixture, method_name, timeout_kwargs, expected, request, recorded_requests
):
    """Each shim forwards the timeout it was actually given.

    Omitting the argument and passing ``None`` both mean "leave the session's
    timeout in charge", so the kwarg must be absent; any other value must be
    forwarded as-is rather than being replaced by a fixed default.
    """
    async with request.getfixturevalue(session_fixture)() as session:
        recorded_requests.clear()
        await getattr(session.api, method_name)(**timeout_kwargs)

        assert len(recorded_requests) == 1
        if expected == "absent":
            assert "timeout" not in recorded_requests[0]
        else:
            assert recorded_requests[0]["timeout"] == expected


async def test_smartzone_system_info_timeout_uses_cached_result(
    create_sz_session, recorded_requests
):
    """SmartZone system info is built entirely from the cached login session.

    It is documented as ignoring ``timeout`` because it issues no requests; if
    that ever stops being true the docstring and this test both need updating.
    """
    async with create_sz_session() as session:
        recorded_requests.clear()
        system_info = await session.api.get_system_info(timeout=7)

        assert system_info["sysinfo"]["version"]
        assert system_info["identity"]["name"]
        assert not recorded_requests, "get_system_info unexpectedly made a request"


@pytest.mark.parametrize(
    "timeout_kwargs, expected",
    [
        ({}, "absent"),
        ({"timeout": None}, "absent"),
        ({"timeout": 7}, aiohttp.ClientTimeout(total=7)),
        ({"timeout": 30}, aiohttp.ClientTimeout(total=30)),
    ],
)
@pytest.mark.parametrize(
    "method_name, endpoint, item",
    [
        (
            "get_active_clients", "client",
            {"clientMac": "f0:1d:ab:ad:d0:0d", "ipAddress": "192.168.0.23",
             "apMac": "8c:7a:15:3e:21:d0"},
        ),
        (
            "get_ap_stats", "ap",
            {"apMac": "8c:7a:15:3e:21:d0", "deviceName": "AnR650",
             "firmwareVersion": "5.2.1.0.123", "serial": "302139502811"},
        ),
    ],
)
async def test_smartzone_stats_forward_timeout_to_every_page(
    create_sz_session, aiohttp_context, recorded_requests, timeout_kwargs, expected,
    method_name, endpoint, item,
):
    """Every page of a paginated query carries the caller's timeout."""
    def _page_response(url, **kwargs):
        page = kwargs["json"]["page"]
        return CallbackResult(
            body=json.dumps({
                "list": [item] * (100 if page == 1 else 1),
                "hasMore": page == 1,
                "totalCount": 101,
            }),
            headers={"Content-Type": "application/json"},
        )

    aiohttp_context.post(
        re.compile(rf"^https://192\.168\.0\.3:8443/wsg/api/public/v9_0/query/{endpoint}\?"),
        callback=_page_response,
    )

    async with create_sz_session() as session:
        recorded_requests.clear()
        results = await getattr(session.api, method_name)(**timeout_kwargs)

        assert len(results) == 101
        assert [call["json"]["page"] for call in recorded_requests] == [1, 2]
        if expected == "absent":
            assert all("timeout" not in call for call in recorded_requests)
        else:
            assert all(
                call["timeout"] == expected for call in recorded_requests
            )
