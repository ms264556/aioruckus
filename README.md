# aioruckus

A Python API which interacts with Ruckus Unleashed and ZoneDirector devices.

Compatible with all Ruckus Unleashed versions, and Ruckus ZoneDirector versions 9.10 onwards.

## How to install

```bash
pip install aioruckus
```

## Usage

Functions are defined within an [async](https://docs.python.org/3/library/asyncio.html) [context manager](https://docs.python.org/3/reference/datamodel.html#context-managers), so you will have to create an event loop instead of calling the functions directly in a shell.

```python
from aioruckus import AjaxSession, SystemStat
import asyncio

async def test_aioruckus():
    
    async with AjaxSession.async_create("<ruckus ip>", "<ruckus user>", "<ruckus password>") as session:
        ruckus = session.api

        wlans = await ruckus.get_wlans()
        wlan_groups = await ruckus.get_wlan_groups()
        aps = await ruckus.get_aps()
        ap_groups = await ruckus.get_ap_groups()
        mesh = await ruckus.get_mesh_info()
        default_system_info = await ruckus.get_system_info()
        all_system_info = await ruckus.get_system_info(SystemStat.ALL)
        active_clients = await ruckus.get_active_clients()
        inactive_clients = await ruckus.get_inactive_clients() # empty on Unleashed
        blocked = await ruckus.get_blocked_client_macs()
        syslog = await api.get_syslog()

        await ruckus.do_block_client("60:ab:de:ad:be:ef")
        await ruckus.do_unblock_client("60:ab:de:ad:be:ef")

        await ruckus.do_disable_wlan("my ssid")
        await ruckus.do_enable_wlan("my ssid")

        await ruckus.do_set_wlan_password("my ssid", "blah>blah<")

        await ruckus.do_hide_ap_leds("24:79:de:ad:be:ef")
        await ruckus.do_show_ap_leds("24:79:de:ad:be:ef")
        
        await api.do_restart_ap("24:79:de:ad:be:ef")


asyncio.run(test_aioruckus())
```

### Other Python APIs for Ruckus Unleashed

This project was originally a fork of [pyuckus](https://github.com/gabe565/pyruckus), which provides similar query functionality by controlling an SSH CLI session.
