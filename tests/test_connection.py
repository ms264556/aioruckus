"""Test connecting to a device and issuing commands."""
import pytest

from aioruckus.exceptions import AuthenticationError
from tests import connect_ruckus


@pytest.mark.asyncio
async def test_connect_success():
    """Normal connection / disconnection."""
    async with connect_ruckus() as ruckus:
        pass

@pytest.mark.asyncio
async def test_authentication_error():
    """Invalid login."""
    with pytest.raises(AuthenticationError):
        async with connect_ruckus(password="bad-password") as ruckus:
            pass

@pytest.mark.asyncio
async def test_connection_error():
    """Non- Unleashed/ZoneDirector host."""
    with pytest.raises(ConnectionError):
        async with connect_ruckus(host="127.0.0.1") as ruckus:
            pass
