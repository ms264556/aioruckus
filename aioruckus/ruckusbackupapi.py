"""Adds Backup methods to RuckusApi"""
from __future__ import annotations

from .abcsession import ConfigItem
from .ajaxtyping import Mesh, SystemInfo
from .backupsession import BackupSession
from .const import SystemStat
from .ruckusconfigurationapi import RuckusConfigurationApi


class RuckusBackupApi(RuckusConfigurationApi):
    """Ruckus ZoneDirector/Unleashed Configuration API"""
    session: BackupSession

    def __init__(self, session: BackupSession):
        """Initialize the API with the given BackupSession."""
        super().__init__(session)

    async def get_system_info(
        self, *sections: SystemStat, timeout: int | None = None
    ) -> dict:
        """Return system information

        Args:
            sections: SystemStat sections to fetch; defaults to
                ``SystemStat.DEFAULT``. Passed positionally — ``timeout`` must
                be a keyword argument.
            timeout: accepted for interface compatibility with
                :class:`RuckusAjaxApi` and ignored; a backup file is read from
                local disk rather than over the network.
        """
        section_keys = self._section_keys(sections)
        system_info = await self._get_conf(ConfigItem.SYSTEM, target_type=SystemInfo)
        metadata = self.session.get_metadata()
        system_info["sysinfo"] = {
            "version": f"{metadata['VERSION']} build {metadata['BUILD']}",
            "version-num": metadata["VERSION"],
            "build-num": metadata["BUILD"],
            "model": metadata["APMODEL"]
        }
        if not section_keys:
            return system_info
        return {k: v for k, v in system_info.items() if k in section_keys}
    
    async def get_mesh_info(self) -> Mesh:
        """Return mesh information"""
        try:
            return await self._get_conf(ConfigItem.MESH_LIST, target_type=Mesh)
        except KeyError:
            return Mesh(id="1", name="Mesh Backbone")
    