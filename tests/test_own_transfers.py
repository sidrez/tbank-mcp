"""Проверки на синтетических счетах. Реальный банк не вызывается."""
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.fernet import Fernet
import requests
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import AccessToken
from tbank_mcp.confirmation import confirmation_mode, confirm_in_client
from tbank_mcp.own_transfers import OwnTransfers, OwnTransferSession, PlanStore, TransferError, install, money


class FakeBank(requests.adapters.BaseAdapter):
    def __init__(self, response=None):
        self.sent = []
        self.response = response or {'resultCode': 'OK', 'payload': {}}

    def send(self, request, **kwargs):
        self.sent.append((request, kwargs))
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(self.response).encode()
        return response

    def close(self):
        pass


def fake_ctx(action='accept', capabilities=None):
    from mcp import types
    caps = capabilities if capabilities is not None else {'elicitation': {'form': {}}}
    session = SimpleNamespace(client_params=SimpleNamespace(capabilities=types.ClientCapabilities.model_validate(caps)))
    session.send_request = AsyncMock(return_value=SimpleNamespace(action=action))
    return SimpleNamespace(request_context=SimpleNamespace(session=session), request_id=10,
                           elicit=AsyncMock(return_value=SimpleNamespace(action=action)))


class OwnTransferTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.env = patch.dict(os.environ, {'TBANK_SESSION': str(self.path / 'session.json')})
        self.env.start()
        self.addCleanup(self.env.stop)
        (self.path / 'session.json').write_text(json.dumps({'refresh_token': 'SYNTHETIC'}))
        self.session = OwnTransferSession(mobile_sessionid='SYNTHETIC', refresh_token='SYNTHETIC')
        self.session.ensure_client_session = lambda: 'CLIENT'
        self.accounts = [dict(id='OWN1111', name='Текущий', accountType='Current', currency={'name': 'RUB'},
                              moneyAmount={'value': 5000}, cards=[{'ucid': 'SYNTHETIC-CARD'}]),
                         dict(id='OWN2222', name='Накопительный', accountType='Saving', currency={'name': 'RUB'})]
        self.session.list_accounts = lambda: self.accounts
        self.calls = []

        def post(endpoint, parameters):
            self.calls.append((endpoint, parameters))
            if endpoint == 'payment_commission':
                return {'resultCode': 'OK', 'payload': {'providerId': 'transfer-inner', 'unfinishedFlag': False,
                    'value': {'value': 0}, 'total': {'value': parameters['moneyAmount']}}}
            return {'resultCode': 'OK', 'payload': {'paymentId': 'SYNTHETIC-ID'}}
        self.session.own_post = post
        self.store = PlanStore(self.path / 'plans.sqlite', Fernet.generate_key())
        self.controller = OwnTransfers(lambda: self.session, self.store, 'https://example.test')

    def prepare(self):
        return self.controller.prepare('OWN1111', 'OWN2222', '10.25')['transfer_id']

    def test_money_rejects_bad_values(self):
        for value in ('nan', 'inf', '-1', '0', '01', '1.001', '1e3', '1,25', True, None):
            with self.subTest(value=value), self.assertRaises(TransferError):
                money(value)

    def test_quote_only_and_encrypted_plan(self):
        identifier = self.prepare()
        self.assertEqual([p for p, _ in self.calls], ['payment_commission'])
        raw = (self.path / 'plans.sqlite').read_bytes()
        self.assertNotIn(b'OWN1111', raw)
        self.assertNotIn(b'10.25', raw)
        self.assertEqual(self.store.get(identifier)[2]['destination'], 'OWN2222')

    def test_reject_foreign_same_credit_currency_and_balance(self):
        for source, destination, amount in [('OTHER', 'OWN2222', '1'), ('OWN1111', 'OWN1111', '1'),
                                            ('OWN1111', 'OWN2222', '5001')]:
            with self.assertRaises(TransferError):
                self.controller.prepare(source, destination, amount)
        for field, value in [('accountType', 'Credit'), ('currency', {'name': 'USD'})]:
            before = self.accounts[1][field]
            self.accounts[1][field] = value
            with self.assertRaises(TransferError):
                self.prepare()
            self.accounts[1][field] = before
        self.assertEqual(self.calls, [])

    def test_reject_commission_changed_total_and_unfinished(self):
        for payload in ({'value': {'value': 1}}, {'total': {'value': 99}}, {'unfinishedFlag': True}):
            def post(endpoint, parameters):
                return {'resultCode': 'OK', 'payload': dict(providerId='transfer-inner', unfinishedFlag=False,
                    value={'value': 0}, total={'value': 10.25}, **{}) | payload}
            self.session.own_post = post
            with self.assertRaises(TransferError):
                self.prepare()

    def test_reject_unsaved_refresh_and_inactive_session(self):
        self.session.refresh_token = 'ROTATED-BUT-NOT-SAVED'
        with self.assertRaises(TransferError):
            self.prepare()
        self.session.refresh_token = 'SYNTHETIC'
        self.session.ensure_client_session = lambda: 'ANONYMOUS'
        with self.assertRaises(TransferError):
            self.prepare()
        self.assertEqual(self.calls, [])

    def test_one_post_and_reprepare_does_not_duplicate_success(self):
        identifier = self.prepare()
        self.assertEqual(self.controller.confirm(identifier)['status'], 'confirmed')
        with self.assertRaises(TransferError):
            self.controller.confirm(identifier)
        self.assertEqual(self.prepare(), identifier)
        self.assertEqual([p for p, _ in self.calls].count('pay'), 1)
        params = next(p for endpoint, p in self.calls if endpoint == 'pay')
        self.assertEqual(params['providerFields'], {'bankContract': 'OWN2222'})
        self.assertEqual(params['moneyAmount'], 10.25)
        self.assertNotIn('paymentType', params)
        self.assertRegex(params['userPaymentId'], r'^\d{13}$')

    def test_unknown_blocks_retry_after_restart(self):
        identifier = self.prepare()
        original = self.session.own_post
        def timeout(endpoint, params):
            if endpoint == 'pay':
                self.calls.append((endpoint, params))
                raise requests.Timeout()
            return original(endpoint, params)
        self.session.own_post = timeout
        self.assertEqual(self.controller.confirm(identifier)['status'], 'unknown')
        restarted = OwnTransfers(lambda: self.session, self.store, 'https://example.test')
        with self.assertRaises(TransferError):
            restarted.prepare('OWN1111', 'OWN2222', '10.25')
        self.assertEqual([p for p, _ in self.calls].count('pay'), 1)

    def test_expiry_and_concurrent_claim(self):
        identifier = self.prepare()
        with self.store.connect() as db:
            db.execute('UPDATE plans SET expires=? WHERE id=?', (time.time() - 1, identifier))
        with self.assertRaises(TransferError):
            self.controller.confirm(identifier)
        identifier = self.prepare()
        def claim():
            try:
                self.store.claim(identifier)
                return True
            except TransferError:
                return False
        with ThreadPoolExecutor(4) as pool:
            self.assertEqual(sum(pool.map(lambda _: claim(), range(8))), 1)

    def test_transport_is_closed_except_exact_owned_request(self):
        session = OwnTransferSession(mobile_sessionid='SYNTHETIC', refresh_token='SYNTHETIC')
        bank = FakeBank()
        session._http.mount('https://', bank)
        for endpoint, params in [('pay', {'provider': 'p2p'}), ('elsewhere', {'provider': 'transfer-inner'})]:
            with self.assertRaises(TransferError):
                session.own_post(endpoint, params)
        with self.assertRaises(Exception):
            session._http.post('https://www.tbank.ru/api/common/v1/pay', data={})
        session.own_post('pay', {'provider': 'transfer-inner', 'account': 'OWN1111',
                               'providerFields': {'bankContract': 'OWN2222'}, 'moneyAmount': 10.25})
        request, options = bank.sent[0]
        url = urlsplit(request.url)
        message = 'POST\n/v1/pay\n' + url.query + '\n' + request.body
        expected = base64.b64encode(hmac.new(b'SYNTHETIC', message.encode(), hashlib.sha256).digest()).decode()
        self.assertEqual(request.headers['x-api-signature'], expected)
        params = json.loads(parse_qs(request.body)['payParameters'][0])
        self.assertEqual(params['provider'], 'transfer-inner')
        self.assertFalse(options['stream'])
        self.assertEqual(len(bank.sent), 1)

    def installed(self):
        mcp = FastMCP('test')
        provider = SimpleNamespace(store=SimpleNamespace(path=self.path / 'oauth.sqlite', cipher=self.store.cipher),
                                   issuer='https://example.test')
        controller = install(mcp, provider, lambda: self.session)
        return mcp, controller

    def test_native_confirmation_is_required_and_arguments_cannot_override(self):
        mcp, controller = self.installed()
        identifier = controller.prepare('OWN1111', 'OWN2222', '10.25')['transfer_id']
        tool = mcp._tool_manager.get_tool('confirm_own_transfer')
        self.assertEqual(set(tool.parameters['properties']), {'transfer_id'})
        token = AccessToken(token='SYNTHETIC', client_id='test', scopes=['bank:read', 'bank:transfer-own'])
        with patch('mcp.server.auth.middleware.auth_context.get_access_token', return_value=token):
            for action in ('decline', 'cancel'):
                ctx = fake_ctx(action)
                self.assertEqual(asyncio.run(tool.fn(identifier, ctx))['status'], 'not_sent')
            self.assertEqual(asyncio.run(tool.fn(identifier, fake_ctx(capabilities={})))['status'], 'not_sent')
            ctx = fake_ctx('accept')
            self.assertEqual(asyncio.run(tool.fn(identifier, ctx))['status'], 'confirmed')
            message = ctx.elicit.call_args.kwargs['message']
            self.assertIn('10.25 RUB', message)
            self.assertIn('····1111', message)
            self.assertIn('····2222', message)
        self.assertEqual([p for p, _ in self.calls].count('pay'), 1)

    def test_read_scope_cannot_pay(self):
        mcp, _ = self.installed()
        token = AccessToken(token='SYNTHETIC', client_id='test', scopes=['bank:read'])
        with patch('mcp.server.auth.middleware.auth_context.get_access_token', return_value=token):
            result = asyncio.run(mcp._tool_manager.get_tool('confirm_own_transfer').fn('anything', fake_ctx()))
        self.assertEqual(result['status'], 'forbidden')
        self.assertEqual(self.calls, [])

    def test_two_clients_share_one_loaded_bank_session(self):
        from tbank_mcp import server
        loaded = []
        def load():
            time.sleep(0.02)
            loaded.append(True)
            return self.session
        with patch.object(server, '_session', None), patch.object(server, '_session_mtime', None), \
                patch.object(server, '_mtime_or_none', return_value=1), \
                patch.object(server, '_load_session', side_effect=load):
            with ThreadPoolExecutor(8) as pool:
                sessions = list(pool.map(lambda _: server._require(), range(8)))
        self.assertEqual(len(loaded), 1)
        self.assertTrue(all(s is self.session for s in sessions))

    def test_openai_legacy_confirmation_and_capability_detection(self):
        ctx = fake_ctx(capabilities={'extensions': {'openai/elicitation': {'form': {}}}})
        self.assertEqual(confirmation_mode(ctx), 'openai')
        self.assertEqual(asyncio.run(confirm_in_client(ctx, 'Synthetic preview')), 'accept')
        request = ctx.request_context.session.send_request.call_args.args[0].model_dump()
        self.assertEqual(request['method'], 'openai/elicitation/create')
        self.assertNotIn('confirmation', request['params']['requestedSchema']['properties'])
        self.assertIsNone(confirmation_mode(fake_ctx(capabilities={'elicitation': {'url': {}}})))
        self.assertEqual(asyncio.run(confirm_in_client(None, 'Preview')), 'unavailable')

    def test_new_permission_does_not_upgrade_existing_read_tokens(self):
        from tbank_mcp.http_server import OwnerOAuth, Store
        with patch.dict(os.environ, {'TBANK_ENABLE_OWN_TRANSFERS': '1'}):
            provider = OwnerOAuth(Store(self.path / 'oauth-test.sqlite', Fernet.generate_key()),
                                  'https://example.test', 'SYNTHETIC-' + 'x' * 40)
        tokens = provider.issue_tokens('synthetic-client', ['bank:read'], 'https://example.test/mcp', 'family')
        access = asyncio.run(provider.load_access_token(tokens.access_token))
        self.assertEqual(access.scopes, ['bank:read'])
        self.assertIn('bank:transfer-own', provider.scopes)


if __name__ == '__main__':
    unittest.main()
