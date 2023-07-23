"""Ruckus AbcSession which connects to Ruckus Unleashed or ZoneDirector backups"""

import io
import struct
import tarfile
from typing import Any

from .abcsession import AbcSession, ConfigItem

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

    async def get_conf_str(self, item: ConfigItem, timeout: int | None = None) -> str:
        return self.backup_tarfile.extractfile(f"etc/airespider/{item.value}.xml").read()
