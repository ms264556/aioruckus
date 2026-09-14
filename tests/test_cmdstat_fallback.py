"""Tests for the TypedDict-driven cmdstat fallback conversions.

Regression guards for the cases that previously went through
``unwrap_xml``: system info sections, docmd ``xmsg`` responses (syslog,
block client), the controller time query, and the getconf/docmd ``conf``
responses. The XML fixtures mirror the raw responses captured from live
Unleashed / ZoneDirector controllers.
"""

import pytest

from aioruckus.ajaxtyping import (
    ApStats,
    Client,
    DocmdResponse,
    Mesh,
    SystemInfo,
    TimeInfo,
    Vap,
)
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
    '<mesh id="1" name="Mesh-Backbone" x-psk="obf" max-hops="3" />'
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
    assert result["psk"] == "nae"  # x-psk decrypted
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


def test_parse_conf_mesh_list_redacts_secrets():
    """With redaction on, the encrypted x-psk is dropped, not decrypted.

    A response only ever carries the encrypted form, so with redaction on
    there is no plaintext key in the result at all.
    """
    result = parse_ajax_response(CONF_MESH_LIST, Mesh, redact_secrets=True)
    assert result["id"] == "1"
    assert result["name"] == "Mesh-Backbone"
    assert result["max-hops"] == "3"
    assert "psk" not in result            # never decrypted
    assert "x-psk" not in result          # and the ciphertext is gone too
    assert "obf" not in repr(result)


def test_redaction_leaves_plain_values_alone():
    """Redaction only drops x- values; ordinary attributes survive."""
    result = parse_ajax_response(CONF_SYSTEM, SystemInfo, redact_secrets=True)
    assert result["identity"]["name"] == "Ruckus-Unleashed"
    assert result["sysinfo"]["serial"] == "162239000115"


def test_redaction_defaults_off():
    """Parsing without opting in still decrypts, for compatibility."""
    assert parse_ajax_response(CONF_MESH_LIST, Mesh)["psk"] == "nae"


# ---------------------------------------------------------------------------
# Numeric conversion driven by the TypedDict
# ---------------------------------------------------------------------------
def test_numeric_attributes_are_converted():
    """Fields declared int/float are converted from the wire's strings."""
    result = parse_ajax_response(CONF_MESH_LIST, Mesh)
    # max-hops is declared str, so it must stay a string
    assert isinstance(result["max-hops"], str)


def test_numeric_conversion_is_best_effort():
    """A value the controller cannot report is left as the string it sent.

    Controllers emit placeholders like "" or N/A for unavailable values;
    inventing a number for those would misreport the device's state.
    """
    xml = (
        '<ajax-response><response type="object" id="ap-list.0.5"><ap-list>'
        '<ap mac="8c:7a:15:3e:21:d0" devname="A" num-sta="12" cpu_util="N/A" '
        'uptime="" />'
        "</ap-list></response></ajax-response>"
    )
    aps = parse_ajax_response(xml, list[ApStats])
    ap = aps[0]
    assert ap["num-sta"] == 12                    # convertible
    assert ap["cpu_util"] == "N/A"                # placeholder preserved
    assert ap["uptime"] == ""                     # empty preserved, not 0
    assert isinstance(ap["cpu_util"], str)


def test_numeric_conversion_of_nested_lists():
    """The conversion reaches fields inside nested list TypedDicts."""
    xml = (
        '<ajax-response><response type="object" id="ap-list.0.5"><ap-list>'
        '<ap mac="8c:7a:15:3e:21:d0" devname="A" num-sta="3">'
        '<radio channel="6" tx-power="-3.5" radio-type="ng" />'
        '<radio channel="36" tx-power="17" radio-type="na" />'
        "</ap>"
        "</ap-list></response></ajax-response>"
    )
    aps = parse_ajax_response(xml, list[ApStats])
    radios = aps[0]["radio"]
    assert [r["channel"] for r in radios] == [6, 36]
    assert all(isinstance(r["channel"], int) for r in radios)
    assert [r["tx-power"] for r in radios] == [-3.5, 17.0]
    assert all(isinstance(r["tx-power"], float) for r in radios)
    # a str-typed field alongside them is untouched
    assert all(isinstance(r["radio-type"], str) for r in radios)


def test_numeric_conversion_applies_to_vap_stats():
    """VAP counters convert, while identifiers stay strings."""
    xml = (
        '<ajax-response><response type="object" id="stamgr.0.5"><apstamgr-stat>'
        '<vap bssid="8c:7a:15:3e:21:d8" ssid="MyWiFi" num-sta="4" '
        'tx-bytes="1024" rx-drop-pkt="2" vap-up="1" />'
        "</apstamgr-stat></response></ajax-response>"
    )
    vaps = parse_ajax_response(xml, list[Vap])
    vap = vaps[0]
    assert vap["num-sta"] == 4
    assert vap["tx-bytes"] == 1024.0
    assert vap["rx-drop-pkt"] == 2
    assert vap["bssid"] == "8c:7a:15:3e:21:d8"     # identifier stays str
    assert vap["ssid"] == "MyWiFi"


def test_redact_secrets_placeholder_keeps_the_key():
    """A string placeholder replaces the value but keeps the field.

    Lets a caller iterate a config's shape without handling the secret.
    """
    result = parse_ajax_response(CONF_MESH_LIST, Mesh, redact_secrets="[redacted]")
    assert result["psk"] == "[redacted]"
    assert "x-psk" not in result          # the ciphertext never appears
    assert result["name"] == "Mesh-Backbone"
    assert result["max-hops"] == "3"      # other fields untouched


def test_redact_secrets_bool_still_drops_the_key():
    """True keeps removing the field entirely, so keys vanish."""
    result = parse_ajax_response(CONF_MESH_LIST, Mesh, redact_secrets=True)
    assert "psk" not in result


def test_redact_secrets_false_still_decrypts():
    """The default is unchanged: obfuscated values are decrypted."""
    assert parse_ajax_response(CONF_MESH_LIST, Mesh, redact_secrets=False)["psk"] == "nae"


def test_client_session_counters_are_numeric():
    """The per-session client counters convert, so callers can do arithmetic."""
    xml = (
        '<ajax-response><response type="object" id="stamgr.0.5"><apstamgr-stat>'
        '<client mac="f0:1d:ab:ad:d0:0d" ap="8c:7a:15:3e:21:d0" ip="192.168.0.23" '
        'hostname="MySmartPhone" total-retries="7" total-rx-crc-errs="3" '
        'tx-drop-data="1" total-rx-bytes="2048" first-assoc="1786771671" />'
        "</apstamgr-stat></response></ajax-response>"
    )
    client = parse_ajax_response(xml, list[Client])[0]
    assert client["total-retries"] == 7.0
    assert client["total-rx-crc-errs"] == 3.0
    assert client["tx-drop-data"] == 1.0
    assert client["total-rx-bytes"] == 2048.0
    assert client["first-assoc"] == 1786771671.0
    # identifiers are unaffected
    assert client["mac"] == "f0:1d:ab:ad:d0:0d"
    assert client["hostname"] == "MySmartPhone"


# ---------------------------------------------------------------------------
# Paired x-/bare secrets
# ---------------------------------------------------------------------------
# A controller asked for DECRYPT_X returns each secret twice: under the x-
# prefixed name and under the plain one, with the same value. Both must be
# handled together, since redacting only the prefixed key would leave the
# plaintext sibling in the result.
PAIRED_MESH = (
    '<ajax-response><response type="object" id="mesh-list.0.5"><mesh-list>'
    '<mesh id="1" name="Mesh-Backbone" x-psk="MeshSecret1" psk="MeshSecret1" '
    'max-hops="3" /></mesh-list></response></ajax-response>'
)


def test_redaction_removes_the_unprefixed_twin_too():
    """Both spellings are removed, so neither name carries the secret."""
    result = parse_ajax_response(
        PAIRED_MESH, Mesh, redact_secrets=True, decrypt_secrets=False
    )
    assert "psk" not in result
    assert "x-psk" not in result
    assert "MeshSecret1" not in repr(result)
    # unrelated fields are untouched
    assert result["max-hops"] == "3"
    assert result["name"] == "Mesh-Backbone"


def test_placeholder_redaction_replaces_the_unprefixed_twin():
    """A placeholder lands on the unprefixed name and the ciphertext goes."""
    result = parse_ajax_response(
        PAIRED_MESH, Mesh, redact_secrets="[redacted]", decrypt_secrets=False
    )
    assert result["psk"] == "[redacted]"
    assert "x-psk" not in result
    assert "MeshSecret1" not in repr(result)


def test_unprefixed_values_are_kept_when_not_redacting():
    """Without redaction the plaintext is exposed under the bare name."""
    result = parse_ajax_response(PAIRED_MESH, Mesh, decrypt_secrets=False)
    assert result["psk"] == "MeshSecret1"
    assert "x-psk" not in result


def test_backup_path_decrypts_instead_of_passing_through():
    """A backup holds the obfuscated form, so it must still be decrypted.

    'xmboqbtt234' is the Caesar shift of 'wlanpass123', as served in a real
    backup and returned decrypted by a real controller.
    """
    xml = (
        '<ajax-response><response type="object" id="wlansvc-list.0.5">'
        '<wlansvc-list><wlansvc name="W" ssid="S" x-passphrase="xmboqbtt234" />'
        '</wlansvc-list></response></ajax-response>'
    )
    result = parse_ajax_response(xml, dict, decrypt_secrets=True)
    assert result["passphrase"] == "wlanpass123"
    assert "x-passphrase" not in result


def test_live_path_does_not_redecrypt_already_plain_values():
    """Live values arrive in the clear; decrypting again would corrupt them.

    'wlanpass123' would become 'uj_ln_qq/01' if the shift were applied twice.
    """
    xml = (
        '<ajax-response><response type="object" id="wlansvc-list.0.5">'
        '<wlansvc-list><wlansvc name="W" ssid="S" x-passphrase="wlanpass123" />'
        '</wlansvc-list></response></ajax-response>'
    )
    result = parse_ajax_response(xml, dict, decrypt_secrets=False)
    assert result["passphrase"] == "wlanpass123"


# ---------------------------------------------------------------------------
# _normalize_encryption: changing a WLAN's encryption mode
# ---------------------------------------------------------------------------
def _wlan_element(encryption, wpa_attrs=None):
    """Build a <wlansvc> element shaped like the controller's."""
    import xml.etree.ElementTree as ET
    wlansvc = ET.Element("wlansvc", {"name": "W", "encryption": encryption})
    if wpa_attrs is not None:
        ET.SubElement(wlansvc, "wpa", wpa_attrs)
    return wlansvc


class _FakeSlot:
    """Stand-in for the session, serving the controller's WLAN template."""

    # mirrors what a real controller returns for wlansvc-standard-template
    TEMPLATE = (
        '<ajax-response><response type="object" id="wlansvc-standard-template">'
        '<wlansvc name="default-standard-wlan" encryption="none"><wpa cipher="aes" '
        'x-passphrase="" x-sae-passphrase="" dynamic-psk="disabled" '
        'dynamic-psk-len="62" dpsk-type="friendly" expire="0" start-point="first-use" '
        'limit-dpsk="disabled" limit-dpsk-val="1" shared-dpsk="disabled" '
        'shared-dpsk-num="2" passphrase="" sae-passphrase="" /></wlansvc>'
        '</response></ajax-response>'
    )

    async def get_conf_str(self, item, timeout=None):
        return self.TEMPLATE


def _normalizer():
    """A RuckusAjaxApi whose session serves the WLAN template.

    _normalize_encryption is async because it may fetch the template when a WLAN
    has no <wpa> block to copy (switching away from "open").
    """
    from aioruckus.ruckusajaxapi import RuckusAjaxApi
    api = RuckusAjaxApi.__new__(RuckusAjaxApi)
    api._RuckusAjaxApi__session = _FakeSlot()
    return api


def _full_wpa(**overrides):
    attrs = {
        "cipher": "aes", "dynamic-psk": "disabled", "dynamic-psk-len": "62",
        "dpsk-type": "friendly", "expire": "0", "start-point": "first-use",
        "limit-dpsk": "disabled", "limit-dpsk-val": "1",
        "shared-dpsk": "disabled", "shared-dpsk-num": "2",
        "passphrase": "wlanpass123", "sae-passphrase": "wlanpass123",
    }
    attrs.update(overrides)
    return attrs


@pytest.mark.asyncio
async def test_encryption_change_preserves_required_wpa_attributes():
    """The rebuilt <wpa> retains the attributes the controller requires."""
    api = _normalizer()
    wlansvc = _wlan_element("wpa23-mixed", _full_wpa())
    await api._normalize_encryption(wlansvc, {"encryption": "wpa3"})

    wpa = wlansvc.find("wpa")
    assert wpa is not None
    assert wpa.get("dynamic-psk-len") == "62"
    assert wpa.get("dpsk-type") == "friendly"
    assert wpa.get("expire") == "0"
    assert wpa.get("limit-dpsk") == "disabled"


@pytest.mark.asyncio
async def test_encryption_change_preserves_the_sae_passphrase():
    """An existing SAE passphrase is carried across an encryption change."""
    api = _normalizer()
    wlansvc = _wlan_element("wpa2", _full_wpa())
    await api._normalize_encryption(wlansvc, {"encryption": "wpa3"})

    wpa = wlansvc.find("wpa")
    assert wpa.get("sae-passphrase") == "wlanpass123"
    assert wpa.get("passphrase") == "wlanpass123"


@pytest.mark.asyncio
async def test_encryption_change_preserves_x_passphrase_attributes():
    """The x- passphrase attributes are inputs the controller expects.

    Dropping them stopped the stored value round-tripping: the controller
    returns x-passphrase only while it holds one, so a rebuild that discarded
    it left the WLAN with no ciphertext at all.
    """
    api = _normalizer()
    attrs = _full_wpa(**{"x-passphrase": "xmboqbtt234", "x-sae-passphrase": "xmboqbtt234"})
    wlansvc = _wlan_element("wpa23-mixed", attrs)
    await api._normalize_encryption(wlansvc, {"encryption": "wpa3"})

    wpa = wlansvc.find("wpa")
    assert wpa.get("x-passphrase") == "xmboqbtt234"
    assert wpa.get("x-sae-passphrase") == "xmboqbtt234"


@pytest.mark.asyncio
async def test_switching_from_open_supplies_wpa_defaults():
    """An open WLAN gaining WPA2 (no <wpa> to copy) gets the template's shape.

    ``_normalize_encryption`` runs before ``_patch_template``, so the patch
    passphrase is not yet on the element here and only the attributes this
    function is responsible for are asserted.
    """
    api = _normalizer()
    wlansvc = _wlan_element("none", None)
    await api._normalize_encryption(
        wlansvc, {"encryption": "wpa2", "wpa": {"passphrase": "wlanpass123"}}
    )

    wpa = wlansvc.find("wpa")
    assert wpa is not None
    assert wpa.get("dynamic-psk-len") == "62"
    assert wpa.get("dpsk-type") == "friendly"
    assert wpa.get("cipher") == "aes"


@pytest.mark.asyncio
async def test_missing_passphrases_still_raise():
    """The guard rails survive: an open WLAN cannot gain WPA2 without a
    passphrase, nor WPA3 without an SAE one."""
    from aioruckus.const import ERROR_PASSPHRASE_MISSING, ERROR_SAEPASSPHRASE_MISSING
    api = _normalizer()
    with pytest.raises(ValueError, match=ERROR_PASSPHRASE_MISSING):
        await api._normalize_encryption(_wlan_element("none", None), {"encryption": "wpa2"})
    with pytest.raises(ValueError, match=ERROR_SAEPASSPHRASE_MISSING):
        await api._normalize_encryption(_wlan_element("none", None), {"encryption": "wpa3"})


@pytest.mark.asyncio
async def test_switching_to_open_removes_the_wpa_element():
    """Open WLANs carry no <wpa>."""
    api = _normalizer()
    wlansvc = _wlan_element("wpa2", _full_wpa())
    await api._normalize_encryption(wlansvc, {"encryption": "none"})
    assert wlansvc.find("wpa") is None
