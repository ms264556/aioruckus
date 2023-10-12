"""Adds Backup methods to RuckusApi"""
from .const import SystemStat
from .abcsession import ConfigItem
from .backupsession import BackupSession
from .ruckusapi import RuckusApi

class RuckusBackupApi(RuckusApi):
    """Ruckus ZoneDirector or Unleashed Configuration, Statistics and Commands API"""

    def __init__(self, session: BackupSession):
        super().__init__(session)

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
        sections = (
            [s for section_list in sections for s in section_list.value]
            if sections
            else SystemStat.DEFAULT.value
        )
        if not sections:
            return system_info
        return {k: v for k, v in system_info.items() if k in sections}
