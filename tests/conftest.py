from aiohttp.client_exceptions import ClientConnectorError
from aioresponses import aioresponses, CallbackResult
from asyncio.exceptions import TimeoutError
import pytest
import re

from aioruckus.ajaxsession import AjaxSession

@pytest.fixture(autouse=True)
def aiohttp_context():
    with aioresponses() as m:
        # Unleashed and ZoneDirector
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
        # Ruckus One
        m.post(
            re.compile(r"^https://api\.(?:eu\.|asia\.)ruckus\.cloud/oauth2/token/5dd1000334cc2a01fcf28a740a6c95cf$"),
            payload={'access_token': 'dummy_bearer_token', 'token_type': 'Bearer', 'expires_in': 7199},
            repeat=True,
        )
        m.post(
            re.compile(r"^https://api\.(?:eu\.|asia\.)ruckus\.cloud/oauth2/token/[a-fA-F0-9]{32}$"),
            status=302,
            repeat=True,
        )
        m.post(
            re.compile(r"^https://api\.elsewhere\.ruckus\.cloud/oauth2/token/[a-fA-F0-9]{32}$"),
            exception=ClientConnectorError(None, OSError()),
            repeat=True,
        )
        m.get(
            re.compile(r"^https://api\.(?:eu\.|asia\.)ruckus\.cloud/venues/aps$"),
            payload=[
                {'mac': '8c:7a:15:3e:21:d0', 'serialNumber': '302139502811', 'name': 'AnR650', 'model': 'R650', 'firmware': '6.2.4.103.259'},
                {'mac': '80:03:84:3f:88:d0', 'serialNumber': '502039500072', 'name': 'My Second R650', 'model': 'R650', 'firmware': '6.2.4.103.259'}
            ],
            repeat=True,
        )
        m.get(
            re.compile(r"^https://api\.(?:eu\.|asia\.)ruckus\.cloud/clients$"),
            payload=[
                {'mac': 'f0:1d:ab:ad:d0:0d', 'hostname': 'MySmartPhone', 'apMac': '8c:7a:15:3e:21:d0', 'ip': '192.168.0.23'},
                {'mac': '0a:23:ab:ad:d0:0d', 'hostname': '', 'apMac': '80:03:84:3f:88:d0', 'ip': '192.168.0.24'}
            ],
            repeat=True,
        )
        m.get(
            re.compile(r"^https://api\.(?:eu\.|asia\.)ruckus\.cloud/tenants/self$"),
            payload={'name': 'dummy_tenant', 'entitlementId': 'ee8771514cca2a7a'},
            repeat=True,
        )
        yield m


@pytest.fixture
def create_r1_session():
    def _create_r1_session():
        return AjaxSession.async_create("https://asia.ruckus.cloud/5dd1000334cc2a01fcf28a740a6c95cf/t/dashboard", "0206ee8771514cca2a7a2f2d144c80f0", "ce97e150e2362f1b07d6c4f6a32934d2")

    return _create_r1_session


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
def set_ajax_results(aiohttp_context):
    def _handle_conf(child_count):
        aiohttp_context.post(
            re.compile(r"^https?://[^/]+/admin/_(?:conf|cmdstat).jsp"),
            callback=unleashed_callback_factory(child_count),
        )

    return _handle_conf
