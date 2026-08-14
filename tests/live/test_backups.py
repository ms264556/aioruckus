"""Tests against real backup archives (no network required).

The ``.bak`` files in ``backups/`` are encrypted tar archives decrypted by
``aioruckus.backupsession``. These tests exercise the configuration API
against firmware-accurate data:

* ``unleashed-200.15.bak``  - Unleashed 200.15.6.212 (R510)
* ``unleashed-200.19.bak``  - Unleashed 200.19.7.11  (R650)
* ``zd-10.5.1.bak``         - ZoneDirector 10.5.1.0 (ZD1200); also the most
                              comprehensive config set
* ``unleashed-200.7.bak``   - Unleashed 200.7.10.202 (R510)

Live-network tests (stats calls against real ZD/Unleashed controllers) will
be added to this directory later.
"""

from contextlib import contextmanager
from pathlib import Path

import pytest

from aioruckus.backupsession import BackupSession
from aioruckus.ruckusconfigurationapi import RuckusConfigurationApi

BACKUP_DIR = Path(__file__).parent / "backups"


@contextmanager
def _open_api(backup: str):
    """Open a backup and yield (session, api)."""
    with BackupSession(str(BACKUP_DIR / backup)) as session:
        yield session, RuckusConfigurationApi(session)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "backup,version,apmodel",
    [
        ("unleashed-200.15.bak", "200.15.6.212", "R510"),
        ("unleashed-200.19.bak", "200.19.7.11", "R650"),
        ("zd-10.5.1.bak", "10.5.1.0", "ZD1200"),
        ("unleashed-200.7.bak", "200.7.10.202", "R510"),
    ],
)
def test_backup_metadata(backup, version, apmodel):
    """Each archive decrypts and reports the expected firmware version."""
    with _open_api(backup) as (session, api):
        metadata = session.get_metadata()
        assert metadata["version"] == version
        assert metadata["apmodel"] == apmodel


# ---------------------------------------------------------------------------
# Configuration method sweep
# ---------------------------------------------------------------------------

# Expected element counts per configuration method for each backup. Counts
# were verified against the archives; methods whose config file is absent
# from an archive fall back to the built-in default (e.g. 83 URL filtering
# categories, 1 default precedence policy) or raise KeyError (see
# MISSING_CONFIGS below).
_EXPECTED = {
    "unleashed-200.15.bak": {
        "get_aps": 1,
        "get_ap_groups": 1,
        "get_wlans": 1,
        "get_wlan_groups": 1,
        "get_urlfiltering_policies": 0,
        "get_urlfiltering_blockingcategories": 83,
        "get_ip4_policies": 5,
        "get_ip6_policies": 5,
        "get_device_policies": 0,
        "get_precedence_policies": 1,
        "get_arc_policies": 0,
        "get_arc_applications": 0,
        "get_arc_ports": 0,
        "get_roles": 2,
        "get_dpsks": 0,
        "get_acls": 0,
        "get_system_info": 2,
        "get_blocked_client_macs": 0,
    },
    "unleashed-200.19.bak": {
        "get_aps": 1,
        "get_ap_groups": 1,
        "get_wlans": 1,
        "get_wlan_groups": 1,
        "get_urlfiltering_policies": 0,
        "get_urlfiltering_blockingcategories": 83,
        "get_ip4_policies": 5,
        "get_ip6_policies": 5,
        "get_device_policies": 0,
        "get_precedence_policies": 1,
        "get_arc_policies": 0,
        "get_arc_applications": 0,
        "get_arc_ports": 0,
        "get_roles": 0,
        "get_dpsks": 0,
        "get_acls": 0,
        "get_system_info": 2,
        "get_blocked_client_macs": 0,
    },
    "zd-10.5.1.bak": {
        "get_aps": 13,
        "get_ap_groups": 9,
        "get_wlans": 24,
        "get_wlan_groups": 17,
        "get_urlfiltering_policies": 2,
        "get_urlfiltering_blockingcategories": 83,
        "get_ip4_policies": 6,
        "get_ip6_policies": 4,
        "get_device_policies": 2,
        "get_precedence_policies": 2,
        "get_arc_policies": 2,
        "get_arc_applications": 1,
        "get_arc_ports": 2,
        "get_roles": 3,
        "get_dpsks": 5,
        "get_acls": 3,
        "get_zerotouch_mesh_ap_serials": 2,
        "get_system_info": 1,
        "get_mesh_info": 3,
        "get_blocked_client_macs": 0,
    },
    "unleashed-200.7.bak": {
        "get_aps": 2,
        "get_ap_groups": 1,
        "get_wlans": 2,
        "get_wlan_groups": 1,
        "get_urlfiltering_policies": 0,
        "get_urlfiltering_blockingcategories": 83,
        "get_ip4_policies": 5,
        "get_ip6_policies": 5,
        "get_device_policies": 0,
        "get_precedence_policies": 1,
        "get_arc_policies": 0,
        "get_arc_applications": 0,
        "get_arc_ports": 0,
        "get_roles": 0,
        "get_dpsks": 10,
        "get_acls": 0,
        "get_system_info": 2,
        "get_blocked_client_macs": 0,
    },
}

_SWEEP = [
    (backup, method, count)
    for backup, methods in _EXPECTED.items()
    for method, count in methods.items()
]


@pytest.mark.asyncio
@pytest.mark.parametrize("backup,method,count", _SWEEP)
async def test_config_method(backup, method, count):
    """Each configuration method parses the expected number of elements."""
    with _open_api(backup) as (session, api):
        result = await getattr(api, method)()
        assert len(result) == count


# Config files absent from a given archive raise KeyError (pre-existing
# behaviour, consistent with a missing member in the backup tar).
_MISSING = [
    ("unleashed-200.15.bak", "get_mesh_info"),
    ("unleashed-200.15.bak", "get_zerotouch_mesh_ap_serials"),
    ("unleashed-200.19.bak", "get_mesh_info"),
    ("unleashed-200.19.bak", "get_zerotouch_mesh_ap_serials"),
    ("unleashed-200.7.bak", "get_mesh_info"),
    ("unleashed-200.7.bak", "get_zerotouch_mesh_ap_serials"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("backup,method", _MISSING)
async def test_missing_config_raises(backup, method):
    """Configs absent from the archive raise KeyError rather than corrupt data."""
    with _open_api(backup) as (session, api):
        with pytest.raises(KeyError):
            await getattr(api, method)()


# ---------------------------------------------------------------------------
# Content: decryption and link resolution (zd-10.5.1 is the comprehensive set)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mesh_psk_decrypted():
    """The encrypted x-psk attribute is decrypted into psk."""
    with _open_api("zd-10.5.1.bak") as (session, api):
        mesh = await api.get_mesh_info()
        assert "psk" in mesh and mesh["psk"]
        assert "x-psk" not in mesh


@pytest.mark.asyncio
async def test_dpsk_passphrase_decrypted():
    """The encrypted x-passphrase attribute is decrypted into passphrase."""
    with _open_api("zd-10.5.1.bak") as (session, api):
        dpsks = await api.get_dpsks()
        assert dpsks
        dpsk = dpsks[0]
        assert "passphrase" in dpsk and dpsk["passphrase"]
        assert "x-passphrase" not in dpsk


@pytest.mark.asyncio
async def test_wlan_policy_links_resolved():
    """WLAN acl/precedence id references are resolved to policy objects."""
    with _open_api("zd-10.5.1.bak") as (session, api):
        wlans = await api.get_wlans()
        assert len(wlans) == 24
        for wlan in wlans:
            assert "acl" in wlan
            assert "precedence" in wlan
            assert "acl-id" not in wlan
            assert "precedence-id" not in wlan
        acl = wlans[0]["acl"]
        assert acl["id"] == "1"
        assert acl["name"] == "System"


@pytest.mark.asyncio
async def test_ap_group_members_resolved():
    """AP group member id references are resolved to AP objects."""
    with _open_api("zd-10.5.1.bak") as (session, api):
        ap_groups = await api.get_ap_groups()
        assert len(ap_groups) == 9
        populated = [g for g in ap_groups if g.get("ap")]
        assert populated
        for ap in populated[0]["ap"]:
            assert "mac" in ap
            assert "serial" in ap
            assert "devname" in ap


@pytest.mark.asyncio
async def test_urlfiltering_blacklist_converted():
    """URL filtering blacklist domain entries become a list of strings."""
    with _open_api("zd-10.5.1.bak") as (session, api):
        policies = await api.get_urlfiltering_policies()
        assert len(policies) == 2
        policy = policies[0]
        assert policy["blacklist"] == ["test.com", "test2.com"]
        assert policy["whitelist"] == ["sub.test.com"]
