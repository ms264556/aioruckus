import re
import json
from unittest.mock import patch
from yarl import URL
from multidict import CIMultiDict, CIMultiDictProxy


class CallbackResult:
    """Mock for aioresponses.CallbackResult."""
    def __init__(self, body="\n", status=200, headers=None):
        self.body = body
        self.status = status
        self.headers = headers or {}


class MockClientResponse:
    """Mock for aiohttp.ClientResponse."""
    def __init__(self, method, url, status=200, headers=None, body="", payload=None, exception=None, callback=None, request_kwargs=None):
        self.method = method
        self.url = URL(url) if isinstance(url, str) else url
        self.status = status
        self._headers = CIMultiDict(headers or {})
        self._body = body
        self._payload = payload
        self.exception = exception
        self.callback = callback
        self.request_kwargs = request_kwargs or {}

        if self.callback:
            res = self.callback(self.url, **self.request_kwargs)
            self.status = getattr(res, "status", 200)
            self._body = getattr(res, "body", "")
            res_headers = getattr(res, "headers", None)
            if res_headers:
                self._headers.update(res_headers)

    @property
    def headers(self):
        return CIMultiDictProxy(self._headers)

    @property
    def content_type(self) -> str:
        ct = self._headers.get("Content-Type", "")
        if not ct:
            if self._payload is not None:
                return "application/json"
            return "text/plain"
        return ct.split(";")[0].strip().lower()

    @property
    def charset(self) -> str | None:
        ct = self._headers.get("Content-Type", "")
        if "charset=" in ct:
            return ct.split("charset=")[-1].split(";")[0].strip()
        return "utf-8"

    @property
    def reason(self) -> str:
        if self.status == 200:
            return "OK"
        if self.status == 302:
            return "Found"
        return "Unknown"

    async def read(self):
        if self.exception:
            raise self.exception
        if isinstance(self._body, str):
            return self._body.encode("utf-8")
        return self._body

    async def text(self, encoding: str | None = None, errors: str = "strict", *args, **kwargs) -> str:
        if self.exception:
            raise self.exception
        if isinstance(self._body, bytes):
            enc = encoding or self.charset or "utf-8"
            return self._body.decode(enc, errors=errors)
        return self._body

    async def json(self, *args, **kwargs):
        if self.exception:
            raise self.exception
        if self._payload is not None:
            return self._payload
        body_text = await self.text()
        return json.loads(body_text)

    @property
    def history(self):
        return []

    async def close(self):
        pass

    async def release(self):
        pass

    async def wait_for_close(self):
        pass
    
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


def merge_params(url: URL, params) -> URL:
    """Merge and sort query parameters into the URL for consistent string matching."""
    if not params:
        return url
    if isinstance(params, dict):
        sorted_params = sorted(params.items())
    elif isinstance(params, (list, tuple)):
        sorted_params = sorted(params)
    else:
        sorted_params = params
    return url.with_query(sorted_params)


class AioResponsesMock:
    """Imitate aioresponses (so we can revert when they fix aiohttp 3.14 compatibility)."""
    def __init__(self):
        self.routes = []
        self._patcher = None

    def post(self, pattern, status=200, headers=None, body="", payload=None, exception=None, callback=None, repeat=True):
        self.add_route("post", pattern, status, headers, body, payload, exception, callback)

    def get(self, pattern, status=200, headers=None, body="", payload=None, exception=None, callback=None, repeat=True):
        self.add_route("get", pattern, status, headers, body, payload, exception, callback)

    def add_route(self, method, pattern, status=200, headers=None, body="", payload=None, exception=None, callback=None):
        self.routes.append({
            "method": method.lower(),
            "pattern": pattern,
            "status": status,
            "headers": headers,
            "body": body,
            "payload": payload,
            "exception": exception,
            "callback": callback,
        })

    def match(self, method, url, **kwargs):
        url_str = str(url)
        method_lower = method.lower()
        # Iterate backwards so that custom routes registered later in test fixtures 
        # override default ones.
        for route in reversed(self.routes):
            if route["method"] == method_lower:
                pattern = route["pattern"]
                match = False
                if isinstance(pattern, re.Pattern):
                    if pattern.search(url_str) or pattern.match(url_str):
                        match = True
                elif isinstance(pattern, str):
                    if pattern == url_str:
                        match = True
                
                if match:
                    return route
        return None

    def __enter__(self):
        async def mock_request(session_self, method, str_or_url, **kwargs):
            url = URL(str_or_url)
            params = kwargs.get("params")
            if params:
                url = merge_params(url, params)

            route = self.match(method, url, **kwargs)
            if not route:
                raise AssertionError(f"No mock route found for {method.upper()} {url} with args {kwargs}")

            if route.get("exception"):
                raise route["exception"]

            return MockClientResponse(
                method=method,
                url=url,
                status=route.get("status", 200),
                headers=route.get("headers"),
                body=route.get("body", ""),
                payload=route.get("payload"),
                exception=route.get("exception"),
                callback=route.get("callback"),
                request_kwargs=kwargs,
            )

        self._patcher = patch("aiohttp.ClientSession._request", mock_request)
        self._patcher.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._patcher:
            self._patcher.stop()
