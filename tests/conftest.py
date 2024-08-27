from aiohttp.client_exceptions import ClientConnectorError
from aioresponses import aioresponses, CallbackResult
from asyncio.exceptions import TimeoutError
import pytest
import re

from aioruckus.ajaxsession import AjaxSession


@pytest.fixture(autouse=True)
def unleashed_context():
    with aioresponses() as m:
        m.head(
            re.compile(r"^https?://192.168.0.2/?$"),
            status=302,
            headers={"Location": "https://my.controller/admin/login.jsp"},
            repeat=True,
        )
        m.head(
            re.compile(r"^https?://192.168.0.1/?$"),
            exception=TimeoutError(),
            repeat=True,
        )
        m.head(
            re.compile(r"^https?://127.0.0.1/?$"),
            exception=ClientConnectorError(None, OSError()),
            repeat=True,
        )
        m.head(
            "https://my.controller/admin/login.jsp?ok=Log+In&password=sp-admin&username=super",
            status=302,
            headers={"HTTP_X_CSRF_TOKEN": "dummy_token"},
            repeat=True,
        )
        m.head(
            re.compile(
                r"^https?://[^/]+/admin/login\.jsp\?ok=.*&password=.*&username=.*"
            ),
            status=200,
            repeat=True,
        )
        m.head(
            "https://my.controller/admin/login.jsp?logout=1", status=302, repeat=True
        )
        yield m


@pytest.fixture
def create_ajax_session():
    def _create_ajax_session():
        return AjaxSession.async_create("192.168.0.2", "super", "sp-admin")

    return _create_ajax_session


def unleashed_callback_factory(child_count):
    def _callback(url, **kwargs):
        data = kwargs["data"]
        if data == "<ajax-request action='getconf' DECRYPT_X='true' updater='ap-list.0.5' comp='ap-list'/>":
            _aps = [
                '<ap mac="8c:7a:15:3e:21:d0" devname="AnR650" model="r650" serial="302139502811" version="200.14.6.1"></ap>',
                '<ap mac="80:03:84:3f:88:d0" devname="My Second R650" model="r650" serial="502039500072" version="200.14.6.1"></ap>',
            ]
            content = f"<ap-list>{''.join(_aps[:child_count])}</ap-list>"
        elif data == "<ajax-request action='getstat' comp='system'><sysinfo/></ajax-request>":
            content = f'<response><sysinfo version="200.14.6.1 build 203" serial="212339000715" /></response>'
        elif data.startswith("<ajax-request action='getstat' comp='system'>"):
            _sysinfos = [
                '<sysinfo version="200.14.6.1 build 203" serial="212339000715" />',
                '<identity name="Ruckus-Unleashed" />',
                '<unleashed-network unleashed-network-token="un2123390007151720757648426" />',
            ]
            content = f"<response>{''.join(_sysinfos)}</response>"
        elif data == "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><client LEVEL='1' /></ajax-request>":
            _clients = [
                '<client mac="f0:1d:ab:ad:d0:0d" ap="8c:7a:15:3e:21:d0" ip="192.168.0.23" hostname="MySmartPhone" />',
                '<client mac="0a:23:ab:ad:d0:0d" ap="80:03:84:3f:88:d0" ip="192.168.0.24" hostname="LaptopComputer" />',
            ]
            content = f"<apstamgr-stat>{''.join(_clients[:child_count])}</apstamgr-stat>"
        elif data.startswith("<ajax-request action='getconf'") and data.endswith(" comp='mesh-list'/>"):
            content = '<mesh-list><mesh id="1" name="Mesh-Backbone" x-psk="" psk="" /></mesh-list>'
        else:
            return CallbackResult(body="\n")
        return CallbackResult(
            body=f'<?xml version="1.0" encoding="utf-8"?><!DOCTYPE ajax-response><ajax-response><response type="object">{content}</response></ajax-response>\n'
        )

    return _callback


@pytest.fixture
def set_conf_results(unleashed_context):
    def _handle_conf(child_count):
        unleashed_context.post(
            re.compile(r"^https?://[^/]+/admin/_(?:conf|cmdstat).jsp"),
            callback=unleashed_callback_factory(child_count),
        )

    return _handle_conf
