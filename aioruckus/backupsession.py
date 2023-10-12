"""Ruckus AbcSession which connects to Ruckus Unleashed or ZoneDirector backups"""

import configparser
import io
import struct
import tarfile
from typing import Any, Mapping, TYPE_CHECKING

from .abcsession import AbcSession, ConfigItem

if TYPE_CHECKING:
    from .ruckusbackupapi import RuckusBackupApi

class BackupSession(AbcSession):
    """Connect to Ruckus Unleashed or ZoneDirector Backup"""

    def __init__(
        self,
        backup_path: str
    ) -> None:
        super().__init__()
        self.backup_file = self.open_backup(backup_path)
        self.backup_tarfile = tarfile.open(fileobj = self.backup_file)

    def __enter__(self) -> "BackupSession":
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.backup_tarfile:
            self.backup_tarfile.close()
        if self.backup_file:
            self.backup_file.close()

    def open_backup(self, backup_path: str) -> io.BytesIO:
        """Return the decrypted backup bytes"""
        (xor_int, xor_flip) = struct.unpack('QQ', b')\x1aB\x05\xbd,\xd6\xf25\xad\xb8\xe0?T\xc58')
        struct_int8 = struct.Struct('Q')
        with open(backup_path, 'rb') as backup_file:
            output_file = io.BytesIO()
            input_data = backup_file.read()
            previous_input_int = 0
            for input_int in struct.unpack_from(str(len(input_data) // 8) + 'Q', input_data):
                output_bytes = struct_int8.pack(previous_input_int ^ xor_int ^ input_int)
                xor_int ^= xor_flip
                previous_input_int = input_int
                output_file.write(output_bytes)
            output_file.seek(0)
            return output_file

    @classmethod
    def create(cls, backup_path: str) -> "BackupSession":
        """Create a default ClientSession & use this to create a BackupSession instance"""
        return BackupSession(backup_path)

    @property
    def api(self) -> "RuckusBackupApi":
        """Return a RuckusBackupApi instance."""
        if not self._api:
            # pylint: disable=import-outside-toplevel
            from .ruckusbackupapi import RuckusBackupApi
            self._api = RuckusBackupApi(self)
        return self._api

    async def get_conf_str(self, item: ConfigItem, timeout: int | None = None) -> str:
        xml = self._get_backup_file(f"etc/airespider/{item.value}.xml")
        return "<ajax-response><response>" + xml + "</response></ajax-response>"

    def get_metadata(self) -> Mapping[str, str]:
        """Return the backup metadata"""
        xml = "[metadata]\n" + self._get_backup_file("metadata")
        config = configparser.ConfigParser()
        config.read_string(xml)
        return config["metadata"]
        
    def _get_backup_file(self, member: str) -> str:
        """Extract a file from the backup and return its contents"""
        return self.backup_tarfile.extractfile(member).read().decode("utf-8")
