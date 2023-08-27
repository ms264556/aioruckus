# aioruckus

A Python API which interacts with Ruckus Unleashed and ZoneDirector devices via their AJAX Web Service interface.  
Configuration information can also be queried from Ruckus Unleashed and ZoneDirector backup files.

Compatible with all Ruckus Unleashed versions, and Ruckus ZoneDirector versions 9.10 onwards.

## How to install

```bash
pip install aioruckus
```

## Usage

Functions are defined within an [async](https://docs.python.org/3/library/asyncio.html) [context manager](https://docs.python.org/3/reference/datamodel.html#context-managers), so you will have to use [asyncio](https://docs.python.org/3/library/asyncio.html) rather than calling the functions directly in a shell.

```python
from aioruckus import AjaxSession, BackupSession, SystemStat
import asyncio

async def test_aioruckus():
    
    async with AjaxSession.async_create("<ruckus ip>", "<ruckus user>", "<ruckus password>") as session:
        ruckus = session.api

        #
        # viewing configuration
        #
        aps = await ruckus.get_aps()
        ap_groups = await ruckus.get_ap_groups()
        wlans = await ruckus.get_wlans()
        wlan_groups = await ruckus.get_wlan_groups() # WLAN Groups are CLI-only on Unleashed
        mesh = await ruckus.get_mesh_info()
        default_system_info = await ruckus.get_system_info()
        all_system_info = await ruckus.get_system_info(SystemStat.ALL)

        #
        # working with with client devices
        #
        active_clients = await ruckus.get_active_clients()
        inactive_clients = await ruckus.get_inactive_clients() # always empty on Unleashed
        blocked_clients = await ruckus.get_blocked_client_macs()
        #
        await ruckus.do_block_client("60:ab:de:ad:be:ef")
        await ruckus.do_unblock_client("60:ab:de:ad:be:ef")
        #
        new_rogues = await ruckus.get_active_rogues()
        known_rogues = await ruckus.get_known_rogues()
        blocked_rogues = await ruckus.get_blocked_rogues()

        #
        # working with APs
        #
        ap_stats = await ruckus.get_ap_stats()
        ap_group_stats = await ruckus.get_ap_group_stats()
        #
        await ruckus.do_hide_ap_leds("24:79:de:ad:be:ef")
        await ruckus.do_show_ap_leds("24:79:de:ad:be:ef")
        #
        await ruckus.do_restart_ap("24:79:de:ad:be:ef")

        #
        # working with WLANs / VAPs
        #
        vap_stats = await ruckus.get_vap_stats()
        wlan_group_stats = await ruckus.get_wlan_group_stats()
        #
        await ruckus.do_disable_wlan("my ssid")
        await ruckus.do_enable_wlan("my ssid")
        #
        await ruckus.do_set_wlan_password("my ssid", "blah>blah<")

        #
        # viewing events / alarms / logs
        #
        all_alarms = await ruckus.get_all_alarms(limit=15)
        #
        all_events = await ruckus.get_all_events(limit=1000)
        ap_events = await ruckus.get_ap_events()
        ap_group_events = await ruckus.get_ap_events("24:79:de:ad:be:ef", "24:59:de:ad:be:ef")
        wlan_events = await ruckus.get_wlan_events()
        wlan_group_events = await ruckus.get_wlan_events("my ssid", "my other ssid", "my third ssid")
        client_events = await ruckus.get_client_events(limit=50)
        wired_client_events = await ruckus.get_wired_client_events()
        #
        syslog = await ruckus.get_syslog()

        #
        # modifying configuration
        #
        await ruckus.do_add_wlan_group("new empty wlangroup", "empty group added by aioruckus")
        await ruckus.do_add_wlan_group("new full wlangroup", "group added by aioruckus", wlans)
        #
        wlan_group_template = next((wlang for wlang in wlan_groups if wlang["name"] == "Default"), None)
        await ruckus.do_clone_wlan_group(wlan_group_template, "Copy of Default")
        #
        await ruckus.do_delete_wlan_group("Copy of Default")
        #
        await ruckus.do_add_wlan("my new sid", passphrase="mypassphrase" )
        await ruckus.do_edit_wlan("my new sid", {"ofdm-rate-only": True})
        #
        template_wlan = next((wlan for wlan in wlans if wlan["name"] == "my ssid"), None)
        await ruckus.do_clone_wlan(template_wlan, "my newer sid")
        await ruckus.do_delete_wlan("my newer sid")

    # viewing backed-up configuration
    with BackupSession.create("<ruckus backup filename>") as session:
        ruckus = session.api

        aps = await ruckus.get_aps()
        ap_groups = await ruckus.get_ap_groups()
        wlans = await ruckus.get_wlans()
        wlan_groups = await ruckus.get_wlan_groups()
        blocked = await ruckus.get_blocked_client_macs()
        mesh = await ruckus.get_mesh_info()
        all_system_info = await ruckus.get_system_info(SystemStat.ALL)

asyncio.run(test_aioruckus())
```

### Other APIs for Ruckus Unleashed

This project was originally a fork of [pyruckus](https://github.com/gabe565/pyruckus), which provides similar Python query functionality by controlling an SSH CLI session.

There is a [Go client](https://github.com/willglynn/ruckus-go) for the latest releases of Unleashed.  
Since it's strongly typed, has good quality comments, and doesn't (yet) contain the large collection of tweaks and hacks needed to work over a wide range of Unleashed and ZoneDirector releases, the [ruckus-go](https://github.com/willglynn/ruckus-go) source code is a great place to understand the required requests and responses you should expect to receive from the AJAX API.

There is also [scrapli](https://github.com/carlmontanari/scrapli) support for the Ruckus Unleashed SSH CLI via [scrapli community](https://github.com/scrapli/scrapli_community).  
Authentication and privilege levels are implemented, but no templates are implemented as of August 2023.
