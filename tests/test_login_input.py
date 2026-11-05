"""Cancelled login must never submit a factor or save a session. No bank IO."""
import contextlib
import io
import unittest
from unittest.mock import Mock, patch

from tbank_mcp import client, login_cli


class LoginInputTests(unittest.TestCase):
    def test_empty_and_invalid_otp_never_reach_bank(self):
        for value in ("", "  ", "abc", "123 abc"):
            with self.subTest(value=value):
                session = Mock(access_token="")
                session.login.return_value = "Следующий шаг — otp."
                with patch.object(login_cli.srv, "_blank_session", return_value=session), \
                     patch.object(login_cli.getpass, "getpass", return_value=value), \
                     patch.object(login_cli.srv, "_save_session") as save, \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(login_cli.login("+79990000000"), 1)
                session.confirm_step.assert_not_called()
                save.assert_not_called()

    def test_otp_success_saves_without_asking_password(self):
        session = Mock(access_token="access")
        with patch.object(login_cli.srv, "_blank_session", return_value=session), \
             patch.object(login_cli.getpass, "getpass", return_value="123456") as prompt, \
             patch.object(login_cli.srv, "_save_session", return_value=True) as save, \
             patch.object(login_cli.srv, "_session", None), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(login_cli.login("+79990000000"), 0)
        session.confirm_step.assert_called_once_with("otp", "123456")
        self.assertEqual(prompt.call_count, 1)
        save.assert_called_once_with(session)

    def test_cli_error_does_not_print_bank_payload(self):
        session = Mock(access_token="")
        session.confirm_step.side_effect = client.TbankApiError("invalid_request", "PRIVATE_AUTH_IDENTIFIER")
        output = io.StringIO()
        with patch.object(login_cli.srv, "_blank_session", return_value=session), \
             patch.object(login_cli.getpass, "getpass", return_value="123456"), \
             contextlib.redirect_stdout(output):
            self.assertEqual(login_cli.login("+79990000000"), 1)
        self.assertIn("invalid_request", output.getvalue())
        self.assertNotIn("PRIVATE_AUTH_IDENTIFIER", output.getvalue())

    def test_client_blocks_empty_factors_before_http(self):
        session = object.__new__(client.MobileSession)
        session._http = Mock()
        for kind in ("otp", "password", "pin"):
            with self.assertRaises(client.TbankApiError):
                session.confirm_step(kind, "   ")
        session._http.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
