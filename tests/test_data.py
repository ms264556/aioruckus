"""Test data returned from a device."""
import pytest

from tests import connect_ruckus


@pytest.mark.asyncio
async def test_current_active_clients():
    async with connect_ruckus() as ruckus:
        clients = await ruckus.api.get_active_clients()
        assert clients
        client = clients[0]
        assert client["mac"]
        assert client["ap"]
        assert client["vap-mac"] # per-radio ssid

@pytest.mark.asyncio
async def test_mesh_info():
    """Test we can get mesh info."""
    async with connect_ruckus() as ruckus:
        mesh_info = await ruckus.api.get_mesh_info()
        assert mesh_info["name"]

@pytest.mark.asyncio
async def test_system_info():
    """Test we can get system info."""
    async with connect_ruckus() as ruckus:
        system_info = await ruckus.api.get_system_info()
        assert system_info["identity"]["name"]
        assert system_info["sysinfo"]["serial"]
        assert system_info["sysinfo"]["version"]
        assert system_info["port"]["ip"]

@pytest.mark.asyncio
async def test_ap_info():
    """Test we can get access point info."""
    async with connect_ruckus() as ruckus:
        ap_info = await ruckus.api.get_aps()
        ap = ap_info[0]
        assert ap["mac"]
        assert ap["model"]
        assert ap["devname"]
        assert ap["gateway"]
        assert ap["radio"][0]["channel"]
        assert ap["radio"][0]["channelization"]
        