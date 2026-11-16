import contextlib
from dataclasses import dataclass, field
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('termux_login', ROOT / 'bin/tbank_termux_login.py')
login = importlib.util.module_from_spec(spec)
spec.loader.exec_module(login)
sys.path.insert(0, str(ROOT))
from tbank_mcp.client import MobileSession, TbankApiError
from tbank_mcp.readonly import ReadOnlyMobileSession


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.output = Path(self.tmp.name) / 'session.json'
        self.session = MobileSession(mobile_sessionid='', refresh_token='', client_id='gorod-app')
        self.session.login = Mock(return_value='Следующий шаг — otp.')
        self.session.confirm_step = Mock(side_effect=self.mint)
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()

    def tearDown(self):
        self.session._http.close()
        self.quiet.__exit__(None, None, None)
        self.tmp.cleanup()

    def mint(self, *args):
        self.session.access_token = 'synthetic-access'
        self.session.refresh_token = 'synthetic-refresh'
        self.session.mobile_sessionid = 'synthetic-session'
        self.session._minted_at = 123.5
        self.session._login_cid = ''

    def run_login(self, values):
        with patch.object(login.getpass, 'getpass', side_effect=values):
            login.authenticate(self.session, TbankApiError, '+79991234567', self.output)

    def test_otp_only_and_mcp_format(self):
        self.run_login(['1234'])
        data = json.loads(self.output.read_text(encoding='utf-8'))
        self.assertNotIn('_http', data)
        self.assertNotIn('confirm_step', data)
        self.assertEqual(data['_minted_at'], 123.5)
        restored = ReadOnlyMobileSession(**data)
        self.assertEqual(restored.refresh_token, 'synthetic-refresh')
        restored._http.close()
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_bank_requested_password_then_pin(self):
        def step(kind, value):
            if kind == 'otp':
                raise TbankApiError('NEXT_STEP', 'Следующий шаг — password.')
            if kind == 'password':
                raise TbankApiError('NEXT_STEP', 'Следующий шаг — pin.')
            self.mint()
        self.session.confirm_step.side_effect = step
        self.run_login(['1234', 'synthetic-password', '1234'])
        self.assertEqual([c.args[0] for c in self.session.confirm_step.call_args_list],
                         ['otp', 'password', 'pin'])
        self.assertTrue(self.output.exists())

    def test_empty_otp_cancels_without_sending(self):
        with self.assertRaises(login.Cancelled):
            self.run_login([''])
        self.session.confirm_step.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_bad_numeric_reprompts_locally(self):
        self.run_login(['abc', '1234'])
        self.session.confirm_step.assert_called_once_with('otp', '1234')
        self.session.login.assert_called_once()

    def test_unknown_step_does_not_send_pin(self):
        self.session.confirm_step.side_effect = TbankApiError('NEXT_STEP', "Следующий шаг — 'captcha'. confirm_pin")
        with self.assertRaises(RuntimeError):
            self.run_login(['1234'])
        self.assertEqual(self.session.confirm_step.call_count, 1)
        self.assertFalse(self.output.exists())

    def test_rejected_otp_does_not_save(self):
        self.session.confirm_step.side_effect = TbankApiError('invalid_code', 'synthetic')
        with self.assertRaises(TbankApiError):
            self.run_login(['1234'])
        self.assertFalse(self.output.exists())

    def test_ping_failure_after_token_exchange_keeps_session(self):
        def step(*args):
            self.mint()
            raise ConnectionError('synthetic')
        self.session.confirm_step.side_effect = step
        self.run_login(['1234'])
        self.assertTrue(self.output.exists())

    def test_partial_tokens_do_not_save(self):
        self.session.confirm_step.side_effect = lambda *args: setattr(self.session, 'access_token', 'synthetic')
        with self.assertRaises(RuntimeError):
            self.run_login(['1234'])
        self.assertFalse(self.output.exists())

    def test_existing_session_not_overwritten(self):
        self.mint()
        self.output.write_text('original', encoding='utf-8')
        with self.assertRaises(FileExistsError):
            login.save_session(self.session, self.output)
        self.assertEqual(self.output.read_text(), 'original')
        self.assertEqual(list(self.output.parent.iterdir()), [self.output])

    def test_login_without_os_link(self):
        with patch.object(os, 'link', None):
            self.run_login(['1234'])
        self.assertTrue(self.output.exists())

    def test_failed_publish_cleans_reservation(self):
        self.mint()
        with patch.object(os, 'replace', side_effect=OSError('synthetic')):
            with self.assertRaises(OSError):
                login.save_session(self.session, self.output)
        self.assertEqual(list(self.output.parent.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
