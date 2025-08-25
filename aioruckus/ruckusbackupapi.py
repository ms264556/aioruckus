"""Adds Backup methods to RuckusApi"""
from __future__ import annotations

from .const import SystemStat
from .abcsession import ConfigItem
from .backupsession import BackupSession
from .ruckusapi import RuckusApi
from .ruckustyping import Mesh

class RuckusBackupApi(RuckusApi):
    """Ruckus ZoneDirector or Unleashed Configuration, Statistics and Commands API"""

    def __init__(self, session: BackupSession):
        super().__init__(session)
        self.session: BackupSession

    async def get_system_info(self, *sections: SystemStat) -> dict:
        """Return system information"""
        system_info = (await self._get_conf(ConfigItem.SYSTEM))["system"]
        metadata = self.session.get_metadata()
        system_info["sysinfo"] = {
            "version": f"{metadata['VERSION']} build {metadata['BUILD']}",
            "version-num": metadata["VERSION"],
            "build-num": metadata["BUILD"],
            "model": metadata["APMODEL"]
        }
        
        section_keys: list[str]
        if sections:
            section_keys = [s for section_list in sections for s in section_list.value]
        else:
            section_keys = SystemStat.DEFAULT.value

        if not section_keys:
            return system_info
        
        return {k: v for k, v in system_info.items() if k in section_keys}
    
    async def get_mesh_info(self) -> Mesh:
        """Return mesh information"""
        try:
            return await self._get_conf(ConfigItem.MESH_LIST)
        except KeyError:
            return Mesh(id="1", name="Mesh Backbone")
    