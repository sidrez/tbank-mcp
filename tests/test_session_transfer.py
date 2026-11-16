"""Зашифрованный перенос и защита от перезаписи; без банковских запросов."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.exceptions import InvalidTag

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('session_transfer', ROOT / 'bin/tbank_session_transfer.py')
transfer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transfer)


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.raw = json.dumps(dict(access_token='synthetic-access', refresh_token='synthetic-refresh',
                                   mobile_sessionid='synthetic-session', device_id='synthetic-device')).encode()
        self.password = b'synthetic-passphrase'

    def test_roundtrip_and_wrong_password(self):
        blob = transfer.encrypt(self.raw, self.password)
        self.assertEqual(transfer.decrypt(blob, self.password), self.raw)
        with self.assertRaises(InvalidTag):
            transfer.decrypt(blob, b'wrong-passphrase')

    def test_tampering_is_rejected(self):
        blob = transfer.encrypt(self.raw, self.password)
        blob = blob[:-1] + bytes([blob[-1] ^ 1])
        with self.assertRaises(InvalidTag):
            transfer.decrypt(blob, self.password)

    def test_incomplete_session_is_rejected(self):
        with self.assertRaises(ValueError):
            transfer.encrypt(b'{}', self.password)

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'session.json'
            transfer.write_new(path, self.raw)
            with self.assertRaises(FileExistsError):
                transfer.write_new(path, b'overwrite')
            self.assertEqual(path.read_bytes(), self.raw)
            self.assertEqual(list(path.parent.iterdir()), [path])


if __name__ == '__main__':
    unittest.main()
