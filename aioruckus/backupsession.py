"""Ruckus AbcSession which connects to Ruckus Unleashed or ZoneDirector backups"""

import configparser
import io
import struct
import tarfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import SEEK_CUR
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
        with open(backup_path, "rb") as backup_file:
            magic = backup_file.read(4)
            if magic == b'RKSF':
                return self.__open_commscope_backup(backup_file)
            else:
                backup_file.seek(0)
                return self.__open_tac_backup(backup_file)

    @classmethod
    def __decrypt_key(cls, cipher_bytes: bytes) -> bytes:
        padded_key = pow(int.from_bytes(cipher_bytes, 'big'), 65537, 23559046888044776627569879690471525499427612616504460325607886880157810091042540109382540840072568820382270758180649018860535002041926018790203547085546162549326945200443019963900872654422143820799219291504478283808912964667353808795633808052022964371726410677357834881346022671448243831605466569511830964339444687659616502868745663064525218488470606514409811838671765944249166136071060850237167429125523755638111097424494275181385870987411479009552515816450089719197508371290305110717762578033949377936003949760003095430389967102852124783026450284389704957901428442687247403657819155956894836033683283023293306459081).to_bytes(256, 'big')
        return padded_key[padded_key.index(b'\x00', 2) + 1:]

    def __open_tac_backup(self, backup_file: io.BufferedReader) -> io.BytesIO:
        """Return the decrypted TAC backup file"""
        (xor_int, xor_flip) = struct.unpack('QQ', b')\x1aB\x05\xbd,\xd6\xf25\xad\xb8\xe0?T\xc58')
        struct_int8 = struct.Struct('Q')
        output_file = io.BytesIO()
        previous_input_int = 0
        input_data = backup_file.read()
        for input_int in struct.unpack_from(str(len(input_data) // 8) + 'Q', input_data):
            output_bytes = struct_int8.pack(previous_input_int ^ xor_int ^ input_int)
            xor_int ^= xor_flip
            previous_input_int = input_int
            output_file.write(output_bytes)
        output_file.seek(0)
        return output_file

    @classmethod
    def __skip_block(cls, backup_file: io.BufferedReader) -> None:
        backup_file.seek(1, SEEK_CUR)
        block_length = int.from_bytes(backup_file.read(4), byteorder='big', signed=False)
        backup_file.seek(block_length, SEEK_CUR)

    @classmethod
    def __get_block_length(cls, backup_file: io.BufferedReader) -> bytes:
        backup_file.seek(1, SEEK_CUR)
        return int.from_bytes(backup_file.read(4), byteorder='big', signed=False)

    def __open_commscope_backup(self, backup_file: io.BufferedReader) -> io.BytesIO:
        """Return the decrypted CommScope Content Manager backup file"""
        backup_file.seek(4, SEEK_CUR)
        encrypted_key = backup_file.read(self.__get_block_length(backup_file))
        key = self.__decrypt_key(encrypted_key)

        self.__skip_block(backup_file) # digest
        self.__skip_block(backup_file) # signature

        decrypted_length = self.__get_block_length(backup_file)
        encrypted_bytes = backup_file.read()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()

        output_file = io.BytesIO()
        output_file.write(decrypted_bytes[:decrypted_length])
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
