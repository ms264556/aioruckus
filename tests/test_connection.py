"""Test connecting to a device and issuing commands."""
import pytest

from aioruckus.exceptions import AuthenticationError
from aioruckus.ajaxsession import AjaxSession


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
    """Invalid login."""
    with pytest.raises(ConnectionError):
        async with AjaxSession.async_create("127.0.0.1", "super", "sp-admin") as session:
            pass

@pytest.mark.asyncio
async def test_connect_no_host_error():
    """Invalid login."""
    with pytest.raises(ConnectionError):
        async with AjaxSession.async_create("192.168.0.1", "super", "sp-admin") as session:
            x = session.api.get_aps()
            pass
