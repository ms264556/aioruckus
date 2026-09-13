import pytest

from aioruckus.const import SystemStat


def check_aps(aps: list):
    for ap in aps:
        assert "mac" in ap, f"'mac' missing in AP: {ap}"
        assert "serial" in ap, f"'serial' missing in AP: {ap}"
        assert "devname" in ap, f"'devname' missing in AP: {ap}"
        assert "model" in ap, f"'model' missing in AP: {ap}"
        assert "version" in ap, f"'version' missing in AP: {ap}"


@pytest.mark.asyncio
async def test_empty_ap_list(create_ajax_session, set_ajax_results):
    """Empty Access point list parsing"""
    async with create_ajax_session() as session:
        set_ajax_results(0)
        aps = await session.api.get_aps()
        assert len(aps) == 0


@pytest.mark.asyncio
async def test_single_ap(create_ajax_session, set_ajax_results):
    """Single Access point list parsing"""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        aps = await session.api.get_aps()
        assert len(aps) == 1
        check_aps(aps)


@pytest.mark.asyncio
async def test_multiple_aps(create_ajax_session, set_ajax_results):
    """Multiple Access point list parsing"""
    async with create_ajax_session() as session:
        set_ajax_results(2)
        aps = await session.api.get_aps()
        assert len(aps) == 2
        check_aps(aps)


def check_clients(clients: list):
    for client in clients:
        assert "hostname" in client, f"'hostname' missing in Client: {client}"
        assert "mac" in client, f"'mac' missing in Client: {client}"
        assert "ip" in client, f"'ip' missing in Client: {client}"
        assert "ap" in client, f"'ap' missing in Client: {client}"


@pytest.mark.asyncio
async def test_empty_client_list(create_ajax_session, set_ajax_results):
    """Empty Active Client list parsing"""
    async with create_ajax_session() as session:
        set_ajax_results(0)
        clients = await session.api.get_active_clients()
        assert len(clients) == 0


@pytest.mark.asyncio
async def test_single_client(create_ajax_session, set_ajax_results):
    """Single Active Client list parsing"""
    async with create_ajax_session() as session:
        set_ajax_results(1)
        clients = await session.api.get_active_clients()
        assert len(clients) == 1
        check_clients(clients)


@pytest.mark.asyncio
async def test_multiple_clients(create_ajax_session, set_ajax_results):
    """Multiple Active Client list parsing"""
    async with create_ajax_session() as session:
        set_ajax_results(2)
        clients = await session.api.get_active_clients()
        assert len(clients) == 2
        check_clients(clients)


@pytest.mark.asyncio
async def test_mesh_info(create_ajax_session, set_ajax_results):
    """Mesh information"""
    async with create_ajax_session() as session:
        set_ajax_results(0)
        mesh_info = await session.api.get_mesh_info()
        assert mesh_info["name"]


@pytest.mark.asyncio
async def test_sys_info(create_ajax_session, set_ajax_results):
    """System information"""
    async with create_ajax_session() as session:
        # bare call
        set_ajax_results(0)
        system_info = await session.api.get_system_info()
        assert system_info["identity"]["name"]
        assert system_info["sysinfo"]["version"]
        assert system_info["sysinfo"]["serial"]
        assert system_info["unleashed-network"]["unleashed-network-token"]
        # sysinfo call
        set_ajax_results(0)
        system_info = await session.api.get_system_info(SystemStat.SYSINFO)
        assert system_info["sysinfo"]["version"]
        assert system_info["sysinfo"]["serial"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "session_fixture", ["create_ajax_session", "create_r1_session", "create_sz_session"]
)
async def test_system_info_rejects_non_systemstat_sections(session_fixture, request):
    """A stray positional is not silently swallowed into ``sections``.

    ``timeout`` is keyword-only because ``sections`` is varargs, so
    ``get_system_info(7)`` has to fail loudly rather than treat the 7 as a
    section and drop it.
    """
    async with request.getfixturevalue(session_fixture)() as session:
        with pytest.raises(TypeError, match="SystemStat"):
            await session.api.get_system_info(7)
        with pytest.raises(TypeError, match="keyword argument"):
            await session.api.get_system_info("sysinfo")


@pytest.mark.asyncio
async def test_system_info_multiple_sections(create_ajax_session, record_ajax_requests):
    """Several sections are flattened into a single request's section list."""
    async with create_ajax_session() as session:
        calls = record_ajax_requests()
        await session.api.get_system_info(SystemStat.SYSINFO, SystemStat.IDENTITY)

    assert calls[-1]["data"] == (
        "<ajax-request action='getstat' comp='system'>"
        "<sysinfo/><identity/></ajax-request>"
    )


@pytest.mark.asyncio
async def test_system_info_default_sections(create_ajax_session, record_ajax_requests):
    """Without sections, the DEFAULT section keys are requested."""
    async with create_ajax_session() as session:
        calls = record_ajax_requests()
        await session.api.get_system_info()

    assert calls[-1]["data"] == (
        "<ajax-request action='getstat' comp='system'>"
        "<identity/><sysinfo/><port/><unleashed-network/></ajax-request>"
    )



@pytest.mark.asyncio
async def test_r1_aps(create_r1_session):
    """Ruckus One Access point list"""
    async with create_r1_session() as session:
        aps = await session.api.get_aps()
        assert len(aps) == 2
        check_aps(aps)

@pytest.mark.asyncio
async def test_r1_clients(create_r1_session):
    """Ruckus One Active Client list"""
    async with create_r1_session() as session:
        clients = await session.api.get_active_clients()
        assert len(clients) == 2
        check_clients(clients)

@pytest.mark.asyncio
async def test_r1_mesh_info(create_r1_session):
    """Ruckus One Active Client list"""
    async with create_r1_session() as session:
        mesh_info = await session.api.get_mesh_info()
        assert mesh_info["name"]

@pytest.mark.asyncio
async def test_r1_system_info(create_r1_session):
    """Ruckus One Active Client list"""
    async with create_r1_session() as session:
        system_info = await session.api.get_system_info()
        # bare call
        assert system_info["identity"]["name"]
        assert system_info["sysinfo"]["version"]
        assert system_info["sysinfo"]["serial"]
        # sysinfo call
        system_info = await session.api.get_system_info(SystemStat.SYSINFO)
        assert system_info["sysinfo"]["version"]
        assert system_info["sysinfo"]["serial"]