"""Session request methods must treat a None timeout as "don't override".

Passing ``timeout=None`` explicitly to aiohttp means "no timeout at all"
(``ClientTimeout(total=None)``), which silently defeats the timeout configured
on the ``ClientSession``. A ``None`` per-call timeout therefore has to be
omitted from the request kwargs entirely, so aiohttp falls back to the
session's own timeout. These tests inspect the kwargs the session actually
hands to aiohttp.
"""

from __future__ import annotations

import aiohttp
import pytest
from multidict import CIMultiDict, CIMultiDictProxy

from aioruckus.ruckusonesession import RuckusOneSession
from aioruckus.smartzonesession import SmartZoneSession
from aioruckus.unleashedsession import UnleashedSession

pytestmark = pytest.mark.asyncio


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
