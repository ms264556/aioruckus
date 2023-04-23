# aioruckus

A Python API which interacts with Ruckus Unleashed and ZoneDirector devices via their AJAX Web Service interface.

Compatible with all Ruckus Unleashed versions, and Ruckus ZoneDirector versions 9.10 onwards.

## How to install

```bash
pip install aioruckus
```

## Usage

Functions are defined within an [async](https://docs.python.org/3/library/asyncio.html) [context manager](https://docs.python.org/3/reference/datamodel.html#context-managers), so you will have to use [asyncio](https://docs.python.org/3/library/asyncio.html) rather than calling the functions directly in a shell.

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
        syslog = await ruckus.get_syslog()

        await ruckus.do_block_client("60:ab:de:ad:be:ef")
        await ruckus.do_unblock_client("60:ab:de:ad:be:ef")

        await ruckus.do_disable_wlan("my ssid")
        await ruckus.do_enable_wlan("my ssid")

        await ruckus.do_set_wlan_password("my ssid", "blah>blah<")

        await ruckus.do_add_wlan("my new sid", passphrase="mypassphrase" )
        await ruckus.do_update_wlan("my new sid", {"ofdm-rate-only": True})

        template_wlan = next((wlan for wlan in wlans if wlan["name"] =="my ssid"), None)
        template_wlan["name"] = "my newer sid"
        template_wlan["ssid"] = "my newer sid"
        await ruckus.do_add_wlan_from_template(new_wlan)

        await ruckus.do_delete_wlan("my newer sid")

        await ruckus.do_hide_ap_leds("24:79:de:ad:be:ef")
        await ruckus.do_show_ap_leds("24:79:de:ad:be:ef")
        
        await ruckus.do_restart_ap("24:79:de:ad:be:ef")


asyncio.run(test_aioruckus())
```

### Other Python APIs for Ruckus Unleashed

This project was originally a fork of [pyuckus](https://github.com/gabe565/pyruckus), which provides similar query functionality by controlling an SSH CLI session.

There is also [scrapli](https://github.com/carlmontanari/scrapli) support for the Ruckus Unleashed SSH CLI via [scrapli community](https://github.com/scrapli/scrapli_community).  
Authentication and privilege levels are implemented, but no templates are implemented as of April 2023.