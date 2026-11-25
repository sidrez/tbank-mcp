"""Реальный HTTP/SSE + stdio, только синтетический банк и диалоги клиента."""
import asyncio
import logging
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_own_transfers import OwnTransferTests
from cryptography.fernet import Fernet
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
import httpx
import uvicorn
from tbank_mcp.http_server import create_app

logging.disable(logging.CRITICAL)


class TransportTests(OwnTransferTests):
    def setUp(self):
        super().setUp()
        self.env2 = patch.dict(os.environ, {'TBANK_ENABLE_OWN_TRANSFERS': '1',
                       'TBANK_OWN_TRANSFER_CONFIRMATION': 'chat' if self._testMethodName.startswith('test_chat_') else 'native',
                       'TBANK_MCP_HERMES_TOKEN_FILE': str(self.path / 'hermes-token')})
        self.env2.start()
        self.addCleanup(self.env2.stop)
        self.get_session = patch('tbank_mcp.server._require', return_value=self.session)
        self.get_session.start()
        self.addCleanup(self.get_session.stop)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        self.port = listener.getsockname()[1]
        self.url = f'http://127.0.0.1:{self.port}/mcp'
        self.app = create_app(f'https://127.0.0.1:{self.port}', 'SYNTHETIC-' + 'x' * 40,
                              Fernet.generate_key(),
                              self.path / 'oauth.sqlite')
        self.web = uvicorn.Server(uvicorn.Config(self.app, log_level='critical', access_log=False))
        self.thread = threading.Thread(target=lambda: self.web.run(sockets=[listener]), daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_web)
        deadline = time.monotonic() + 5
        while not self.web.started and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.web.started)

    def stop_web(self):
        self.web.should_exit = True
        self.thread.join(5)

    async def exercise(self, client, action, messages):
        await client.initialize()
        tools = (await client.list_tools()).tools
        self.assertEqual(len(tools), 20)
        result = await client.call_tool('prepare_own_transfer', dict(source_account_id='OWN1111',
                                         destination_account_id='OWN2222', amount_rub='10.25'))
        data = result.structuredContent or json.loads(result.content[0].text)
        identifier = data['transfer_id']
        result = await client.call_tool('confirm_own_transfer', {'transfer_id': identifier})
        data = result.structuredContent or json.loads(result.content[0].text)
        self.assertEqual(data['status'], 'confirmed' if action == 'accept' else 'not_sent')
        self.assertEqual(len(messages), 1)
        self.assertIn('10.25 RUB', messages[0])
        self.assertIn('····1111', messages[0])

    def test_http_sse_native_confirmation(self):
        async def run():
            messages = []
            async def elicit(context, params):
                messages.append(params.message)
                return types.ElicitResult(action='accept', content={})
            token = self.app.state.oauth.hermes_token
            async with httpx.AsyncClient(headers={'Authorization': 'Bearer ' + token}, trust_env=False) as http:
                metadata = await http.get(self.url.replace('/mcp', '/.well-known/oauth-protected-resource/mcp'))
                self.assertEqual(metadata.json()['scopes_supported'], ['bank:read', 'bank:transfer-own'])
                async with streamable_http_client(self.url, http_client=http) as (r, w, _):
                    async with ClientSession(r, w, elicitation_callback=elicit) as client:
                        await self.exercise(client, 'accept', messages)
        asyncio.run(run())
        self.assertEqual([p for p, _ in self.calls].count('pay'), 1)

    def test_stdio_hermes_forwards_cancel(self):
        async def run():
            messages = []
            async def elicit(context, params):
                messages.append(params.message)
                return types.ElicitResult(action='cancel')
            env = {**os.environ, 'TBANK_MCP_HERMES_URL': self.url, 'PYTHONUTF8': '1'}
            params = StdioServerParameters(command=sys.executable, args=['-m', 'tbank_mcp.hermes_bridge'], env=env)
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w, elicitation_callback=elicit) as client:
                    await self.exercise(client, 'cancel', messages)
        asyncio.run(run())
        self.assertEqual([p for p, _ in self.calls].count('pay'), 0)

    async def exercise_chat(self, client):
        await client.initialize()
        names = {t.name for t in (await client.list_tools()).tools}
        self.assertEqual(len(names), 20)
        self.assertIn('execute_own_transfer', names)
        self.assertNotIn('confirm_own_transfer', names)
        result = await client.call_tool('prepare_own_transfer', dict(source_account_id='OWN1111',
            destination_account_id='OWN2222', amount_rub='10.25'))
        data = result.structuredContent or json.loads(result.content[0].text)
        self.assertEqual(data['status'], 'prepared')
        self.assertNotIn('pay', [p for p, _ in self.calls])
        identifier = data['transfer_id']
        for _ in range(2):
            result = await client.call_tool('execute_own_transfer', {'transfer_id':identifier})
            data = result.structuredContent or json.loads(result.content[0].text)
            self.assertEqual(data['status'], 'confirmed')

    def test_chat_http_executes_once_without_elicitation(self):
        async def run():
            token = self.app.state.oauth.hermes_token
            async with httpx.AsyncClient(headers={'Authorization':'Bearer '+token}, trust_env=False) as http:
                health = (await http.get(self.url.replace('/mcp','/healthz'))).json()
                self.assertEqual(health['execution_policy'], 'chat')
                self.app.state.oauth.store.put('pending', 'SYNTHETIC-CONSENT',
                    {'params':{'scopes':['bank:read','bank:transfer-own']}}, time.time()+60)
                consent = await http.get(self.url.replace('/mcp','/consent'), params={'request':'SYNTHETIC-CONSENT'})
                self.assertEqual(consent.status_code, 200)
                self.assertIn('без дополнительной формы подтверждения', consent.text)
                self.assertNotIn('Каждый перевод потребует подтверждения кнопкой', consent.text)
                async with streamable_http_client(self.url, http_client=http) as (read, write, _):
                    async with ClientSession(read, write) as client:
                        await self.exercise_chat(client)
        asyncio.run(run())
        self.assertEqual([p for p, _ in self.calls].count('pay'), 1)

    def test_chat_stdio_executes_once_without_elicitation(self):
        async def run():
            env = {**os.environ, 'TBANK_MCP_HERMES_URL':self.url, 'PYTHONUTF8':'1'}
            options = StdioServerParameters(command=sys.executable, args=['-m','tbank_mcp.hermes_bridge'], env=env)
            async with stdio_client(options) as (read, write):
                async with ClientSession(read, write) as client:
                    await self.exercise_chat(client)
        asyncio.run(run())
        self.assertEqual([p for p, _ in self.calls].count('pay'), 1)


if __name__ == '__main__':
    # Общие проверки импортированы как fixture; повторно здесь их не запускаем.
    unittest.main(defaultTest=['TransportTests.test_http_sse_native_confirmation',
                               'TransportTests.test_stdio_hermes_forwards_cancel',
                               'TransportTests.test_chat_http_executes_once_without_elicitation',
                               'TransportTests.test_chat_stdio_executes_once_without_elicitation'])
