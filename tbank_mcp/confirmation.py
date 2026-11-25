"""Подтверждение пользователем через MCP; отсутствие диалога запрещает платёж."""
from typing import Literal

from mcp.shared.message import ServerMessageMetadata
from pydantic import BaseModel, RootModel


class EmptyConfirmation(BaseModel):
    """Кнопка Accept подтверждает параметры из сообщения, полей ввода нет."""


class OpenAIFormRequest(BaseModel):
    method: Literal['openai/elicitation/create'] = 'openai/elicitation/create'
    params: dict


class OpenAIFormEnvelope(RootModel[OpenAIFormRequest]):
    pass


class OpenAIFormResult(BaseModel):
    action: Literal['accept', 'decline', 'cancel']
    content: dict | None = None


def confirmation_mode(ctx):
    try:
        params = ctx.request_context.session.client_params
        capabilities = params.capabilities.model_dump(exclude_none=True)
    except (AttributeError, ValueError):
        return None
    extensions = capabilities.get('extensions') or capabilities.get('experimental') or {}
    if isinstance(extensions.get('openai/elicitation'), dict) and 'form' in extensions['openai/elicitation']:
        return 'openai'
    elicitation = capabilities.get('elicitation')
    if isinstance(elicitation, dict) and ('form' in elicitation or not elicitation):
        return 'mcp'
    return None


async def confirm_in_client(ctx, message):
    """Ответ принимается по обратному RPC от клиента, а не из аргументов модели."""
    mode = confirmation_mode(ctx)
    try:
        if mode == 'mcp':
            result = await ctx.elicit(message=message, schema=EmptyConfirmation)
        elif mode == 'openai':
            # Прямые подключения с MCP <=2025-11-25: официальный legacy API OpenAI.
            result = await ctx.request_context.session.send_request(
                OpenAIFormEnvelope(OpenAIFormRequest(params={
                    'mode': 'form', 'message': message,
                    'requestedSchema': {'type': 'object', 'properties': {}},
                })), OpenAIFormResult,
                metadata=ServerMessageMetadata(related_request_id=ctx.request_id))
        else:
            return 'unavailable'
    except Exception:
        return 'error'
    return result.action
