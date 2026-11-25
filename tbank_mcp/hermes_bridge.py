"""Stdio-мост Hermes к единственному HTTP MCP. Банковскую сессию не загружает."""
import asyncio
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit

import httpx
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from .confirmation import confirmation_mode


async def main():
    path = Path(os.environ.get('TBANK_MCP_HERMES_TOKEN_FILE', '/var/lib/tbank-readonly/hermes-token'))
    token = path.read_text(encoding='utf-8').strip()
    url = os.environ.get('TBANK_MCP_HERMES_URL', 'http://127.0.0.1:8954/mcp')
    target = urlsplit(url)
    if (target.scheme != 'http' or target.hostname != '127.0.0.1' or target.path != '/mcp'
            or target.username or target.password or target.query or target.fragment):
        raise ValueError('Hermes bridge requires a loopback MCP URL')
    bridge = Server('tbank-hermes-bridge')
    active = {}
    lock = asyncio.Lock()

    async def elicit(context, params):
        # HTTP-клиент и stdio-сервер обслуживаются разными задачами: передаём
        # контекст явно под lock, чтобы диалог не попал к другому tools/call.
        ctx = active.get('ctx')
        if ctx is None or getattr(params, 'mode', 'form') != 'form':
            return types.ElicitResult(action='cancel')
        class ClientContext:
            request_context = ctx
        if confirmation_mode(ClientContext()) != 'mcp':
            return types.ElicitResult(action='cancel')
        return await ctx.session.elicit_form(params.message, params.requestedSchema,
                                            related_request_id=ctx.request_id)
    async with httpx.AsyncClient(headers={'Authorization': 'Bearer ' + token}, timeout=90, trust_env=False) as http:
        async with streamable_http_client(url, http_client=http) as (read, write, _):
            async with ClientSession(read, write, elicitation_callback=elicit) as remote:
                await remote.initialize()

                @bridge.list_tools()
                async def tools():
                    return (await remote.list_tools()).tools

                @bridge.call_tool()
                async def call(name, arguments):
                    async with lock:
                        active['ctx'] = bridge.request_context
                        try:
                            return await remote.call_tool(name, arguments or {})
                        except Exception:
                            return types.CallToolResult(isError=True, content=[types.TextContent(type='text', text='Т-Банк недоступен. Не повторяйте неподтверждённый перевод.')])
                        finally:
                            active.clear()

                async with stdio_server() as (incoming, outgoing):
                    await bridge.run(incoming, outgoing, bridge.create_initialization_options())


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except Exception:
        print('Не удалось подключить Hermes к HTTP MCP Т-Банка. Проверьте службу и закрытый token-файл.', file=sys.stderr)
        sys.exit(1)
