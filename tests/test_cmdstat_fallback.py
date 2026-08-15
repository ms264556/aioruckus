"""Tests for the TypedDict-driven cmdstat fallback conversions.

Regression guards for the cases that previously went through
``unwrap_xml``: system info sections, docmd ``xmsg`` responses (syslog,
block client), the controller time query, and the getconf/docmd ``conf``
responses. The XML fixtures mirror the raw responses captured from live
Unleashed / ZoneDirector controllers.
"""

import pytest

from aioruckus.ajaxtyping import DocmdResponse, Mesh, SystemInfo, TimeInfo
from aioruckus.const import SystemStat
from aioruckus.unleashedtojson import parse_ajax_response

SYSINFO_MULTI = (
    '<ajax-response><response type="object" id="DEH"><response>'
    '<identity name="Ruckus-Unleashed" domain="" />'
    '<sysinfo uptime="3252" version="200.19.7.11 build 283" serial="162239000115" />'
    '<port name="br0" mac="D4:BD:4F:14:82:A0" ip="10.222.1.109" />'
    '<unleashed-network unleashed-network-token="un1622390001151777545913215" />'
    "</response></response></ajax-response>"
)

SYSINFO_SINGLE = (
    '<ajax-response><response type="object"><response>'
    '<sysinfo version="200.14.6.1 build 203" serial="212339000715" />'
    "</response></response></ajax-response>"
)

TIME_RESPONSE = (
    '<ajax-response><response type="object" id="DEH"><response>'
    '<time by-ntp="true" time="1786765963" ntp1="ntp.ruckuswireless.com" />'
    "</response></response></ajax-response>"
)

SYSLOG_RESPONSE = (
    '<ajax-response><response type="object" id="system.1786765962096.4678">'
    '<xmsg type="0" msg="" res="Aug 15 03:59:49 syslogd..." /></response></ajax-response>'
)

BLOCK_RESPONSE = (
    '<ajax-response><response type="object" id="DEH">'
    '<xmsg type="-1" msg="hv" lmsg="~hv~" /></response></ajax-response>'
)


def test_parse_system_info_multi_section():
    """Multi-section system info keeps every requested section."""
    result = parse_ajax_response(SYSINFO_MULTI, SystemInfo)
    assert result["identity"]["name"] == "Ruckus-Unleashed"
    assert result["sysinfo"]["version"] == "200.19.7.11 build 283"
    assert result["port"]["ip"] == "10.222.1.109"
    assert result["unleashed-network"]["unleashed-network-token"]


def test_parse_system_info_single_section():
    """A single section stays wrapped under its section name."""
    result = parse_ajax_response(SYSINFO_SINGLE, SystemInfo)
    assert result["sysinfo"]["version"] == "200.14.6.1 build 203"
    assert result["sysinfo"]["serial"] == "212339000715"


def test_parse_time_info():
    """Time query parses to the time element with its attrs."""
    result = parse_ajax_response(TIME_RESPONSE, TimeInfo)
    assert result["time"]["time"] == "1786765963"
    assert result["time"]["by-ntp"] == "true"


def test_parse_syslog_xmsg():
    """docmd get-syslog parses to an xmsg response carrying res."""
    result = parse_ajax_response(SYSLOG_RESPONSE, DocmdResponse)
    assert result["xmsg"]["res"].startswith("Aug 15")
    assert result["xmsg"]["type"] == "0"


def test_parse_block_xmsg():
    """docmd block parses to an xmsg response carrying the error type."""
    result = parse_ajax_response(BLOCK_RESPONSE, DocmdResponse)
    assert result["xmsg"]["type"] == "-1"
    assert result["xmsg"]["lmsg"] == "~hv~"


def test_parse_dict_and_list_targets():
    """Bare dict / list targets pass the payload through."""
    as_dict = parse_ajax_response(SYSINFO_MULTI, dict)
    assert as_dict["identity"]["name"] == "Ruckus-Unleashed"
    as_list = parse_ajax_response(SYSINFO_MULTI, list)
    assert isinstance(as_list, list)
    assert as_list[0]["identity"]["name"] == "Ruckus-Unleashed"


CONF_SYSTEM = (
    '<ajax-response><response type="object" id="system.0.5"><system>'
    '<identity name="Ruckus-Unleashed" domain="" />'
    '<sysinfo version="200.19.7.11 build 283" serial="162239000115" />'
    '<unleashed-network unleashed-network-token="un1622390001151777545913215" />'
    "</system></response></ajax-response>"
)

CONF_MESH_LIST = (
    '<ajax-response><response type="object" id="mesh-list.0.5"><mesh-list>'
    '<mesh id="1" name="Mesh-Backbone" x-psk="obf" max-hops="3" psk="obf" />'
    "</mesh-list></response></ajax-response>"
)

CONF_DOCMD_ERROR = (
    '<ajax-response><response type="object" id="DEH">'
    '<xmsg type="-1" msg="bad" lmsg="Command failed" /></response></ajax-response>'
)


def test_parse_conf_system():
    """getconf system unwraps the <system> wrapper to its sections."""
    result = parse_ajax_response(CONF_SYSTEM, SystemInfo)
    assert result["identity"]["name"] == "Ruckus-Unleashed"
    assert result["sysinfo"]["serial"] == "162239000115"
    assert result["unleashed-network"]["unleashed-network-token"]


def test_parse_conf_mesh_list():
    """getconf mesh-list unwraps to the single mesh dict."""
    result = parse_ajax_response(CONF_MESH_LIST, Mesh)
    assert result["id"] == "1"
    assert result["name"] == "Mesh-Backbone"
    assert result["psk"] == "obf"  # x-psk decrypted
    assert "x-psk" not in result


def test_parse_conf_docmd_error():
    """A failed conf mutation parses to an xmsg response with lmsg."""
    result = parse_ajax_response(CONF_DOCMD_ERROR, DocmdResponse)
    assert result["xmsg"]["type"] == "-1"
    assert result["xmsg"]["lmsg"] == "Command failed"


@pytest.mark.asyncio
async def test_get_syslog(create_ajax_session, set_ajax_results):
    """get_syslog returns the xmsg res string from the controller."""
    async with create_ajax_session() as session:
        set_ajax_results(0)
        syslog = await session.api.get_syslog()
        assert isinstance(syslog, str)
        assert syslog.startswith("Aug 15")


@pytest.mark.asyncio
async def test_do_block_client(create_ajax_session, set_ajax_results):
    """do_block_client issues the block-client fallback on xmsg type -1."""
    async with create_ajax_session() as session:
        set_ajax_results(0)
        # mock returns xmsg type="-1", so the fallback block-client call runs
        await session.api.do_block_client("AA:BB:CC:DD:EE:FF")


@pytest.mark.asyncio
async def test_conf_get_system_info(create_ajax_session, set_ajax_results):
    """get_system_info via getconf parses the system sections."""
    async with create_ajax_session() as session:
        set_ajax_results(0)
        system_info = await session.api.get_system_info(SystemStat.DEFAULT)
        assert system_info["identity"]["name"] == "Ruckus-Unleashed"
        assert system_info["sysinfo"]["serial"] == "212339000715"


@pytest.mark.asyncio
async def test_conf_get_mesh_info(create_ajax_session, set_ajax_results):
    """get_mesh_info via getconf unwraps to the mesh dict."""
    async with create_ajax_session() as session:
        set_ajax_results(0)
        mesh_info = await session.api.get_mesh_info()
        assert mesh_info["name"] == "Mesh-Backbone"
        assert "psk" in mesh_info


@pytest.mark.asyncio
async def test_do_conf_raises_on_error_xmsg(create_ajax_session, set_ajax_results):
    """_do_conf raises ValueError with lmsg when the controller reports failure."""
    async with create_ajax_session() as session:
        set_ajax_results(0)
        with pytest.raises(ValueError, match="Command failed"):
            await session.api._do_conf(
                "<ajax-request action='updobj' comp='acl-list' updater='blocked-clients'>"
                "<acl id='1' /></ajax-request>"
            )
