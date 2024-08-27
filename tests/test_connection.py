"""Test connecting to a device and issuing commands."""
import pytest

from aioruckus.exceptions import AuthenticationError
from aioruckus.ajaxsession import AjaxSession

@pytest.mark.asyncio
async def test_r1_connect_success():
    """Normal Ruckus One connection / disconnection."""
    async with AjaxSession.async_create("https://asia.ruckus.cloud/5dd1000334cc2a01fcf28a740a6c95cf/t/dashboard", "0206ee8771514cca2a7a2f2d144c80f0", "ce97e150e2362f1b07d6c4f6a32934d2") as session:
        pass

@pytest.mark.asyncio
async def test_r1_connect_authentication_error():
    """Invalid login."""
    with pytest.raises(AuthenticationError):
        async with AjaxSession.async_create("https://asia.ruckus.cloud/4dd1000334cc2a01fcf28a740a6c95cf/t/dashboard", "0206ee8771514cca2a7a2f2d144c80f0", "ce97e150e2362f1b07d6c4f6a32934d2") as session:
            pass

@pytest.mark.asyncio
async def test_r1_connect_no_webserver_error():
    """Host Missing."""
    with pytest.raises(ConnectionError):
        async with AjaxSession.async_create("https://elsewhere.ruckus.cloud/5dd1000334cc2a01fcf28a740a6c95cf/t/dashboard", "0206ee8771514cca2a7a2f2d144c80f0", "ce97e150e2362f1b07d6c4f6a32934d2") as session:
            pass

@pytest.mark.asyncio
async def test_connect_success():
    """Normal connection / disconnection."""
    async with AjaxSession.async_create("192.168.0.2", "super", "sp-admin") as session:
        pass

@pytest.mark.asyncio
async def test_connect_authentication_error():
    """Invalid login."""
    with pytest.raises(AuthenticationError):
        async with AjaxSession.async_create("192.168.0.2", "wrong", "password") as session:
            pass

@pytest.mark.asyncio
async def test_connect_no_webserver_error():
    """Connection Refused."""
    with pytest.raises(ConnectionError):
        async with AjaxSession.async_create("127.0.0.1", "super", "sp-admin") as session:
            pass

@pytest.mark.asyncio
async def test_connect_no_host_error():
    """Host Missing."""
    with pytest.raises(ConnectionError):
        async with AjaxSession.async_create("192.168.0.1", "super", "sp-admin") as session:
            x = session.api.get_aps()
            pass
