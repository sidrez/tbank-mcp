"""Собственные RUB-переводы с подтверждением в клиенте MCP.

Контракт веб-API проверен на обезличенной записи от 25.11.2026.
Неизвестный исход не повторяется. Подтверждение не является аргументом tool.
"""
from contextvars import ContextVar
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import urlencode, urlsplit

from cryptography.fernet import Fernet
import requests
from starlette.concurrency import run_in_threadpool
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations

from .client import _MINT_LOCK
from .readonly import ReadOnlyHTTP, ReadOnlyMobileSession, denied

_BOUND_REQUEST = ContextVar('own_transfer_request', default=None)
WEB = 'https://www.tbank.ru/api/common/v1/'
OWN_SCOPE = 'bank:transfer-own'


class TransferError(Exception):
    """Сообщение содержит только заранее заданный безопасный текст."""


def money(value):
    if not re.fullmatch(r'(?:0|[1-9][0-9]{0,8})(?:\.[0-9]{1,2})?', str(value)):
        raise TransferError('Укажите положительную сумму с точностью до копейки.')
    try:
        amount = Decimal(str(value))
    except InvalidOperation:
        raise TransferError('Неверная сумма.') from None
    if not amount.is_finite() or amount <= 0:
        raise TransferError('Сумма должна быть больше нуля.')
    return amount.quantize(Decimal('0.01'))


def number(value):
    amount = Decimal(str(value))
    if not amount.is_finite():
        raise TransferError('Банк вернул неверную сумму.')
    return amount


class OwnTransferHTTP(ReadOnlyHTTP):
    def send(self, request, **kwargs):
        bound = _BOUND_REQUEST.get()
        url = urlsplit(request.url)
        if bound and (request.method, request.url, request.body) == bound:
            if (url.scheme, url.netloc, url.path) not in {
                ('https', 'www.tbank.ru', '/api/common/v1/payment_commission'),
                ('https', 'www.tbank.ru', '/api/common/v1/pay'),
            }:
                denied()
            return requests.Session.send(self, request, **kwargs)
        return super().send(request, **kwargs)


class OwnTransferSession(ReadOnlyMobileSession):
    def _new_http(self):
        return OwnTransferHTTP()

    def own_post(self, endpoint, parameters):
        if endpoint not in ('payment_commission', 'pay') or parameters.get('provider') != 'transfer-inner':
            raise TransferError('Разрешены только переводы между своими счетами.')
        fields = {'payParameters': json.dumps(parameters, ensure_ascii=False, separators=(',', ':'))}
        # Не воспроизводим чужой browser fingerprint или performance-телеметрию.
        if endpoint == 'pay':
            fields.update({'javaEnabled': 'false', 'javaScriptEnabled': 'true',
                           'language': 'ru', 'timezone': '180', 'colorDepth': '24'})
        query = {'wuid': self.device_id, 'origin': 'web,ib5,platform', 'appName': 'supreme',
                 'appVersion': '0.0.1', 'platform': 'web', 'sessionid': self.mobile_sessionid}
        prepared = self._http.prepare_request(requests.Request('POST', WEB + endpoint,
            params=query, data=fields, headers={'Cookie': self._cookie_for('https://www.tbank.ru')}))
        if endpoint == 'pay':
            u = urlsplit(prepared.url)
            prepared.headers['x-api-signature'] = self._sign('POST', u.path, u.query, prepared.body)
        context = _BOUND_REQUEST.set(('POST', prepared.url, prepared.body))
        try:
            settings = self._http.merge_environment_settings(prepared.url, {}, None, None, None)
            response = self._http.send(prepared, timeout=25, allow_redirects=False, **settings)
            if response.status_code != 200:
                raise TransferError('Банк не подтвердил запрос. Не повторяйте перевод автоматически.')
            result = response.json()
            if not isinstance(result, dict):
                raise TransferError('Неожиданный ответ банка.')
            return result
        finally:
            _BOUND_REQUEST.reset(context)


class PlanStore:
    def __init__(self, path, key):
        self.path = str(path)
        self.cipher = key if isinstance(key, Fernet) else Fernet(key.encode() if isinstance(key, str) else key)
        self.lock = threading.RLock()
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS plans (id TEXT PRIMARY KEY, fingerprint TEXT, state TEXT, expires REAL, payload BLOB)')
        os.chmod(path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=20)
        try:
            with db:
                yield db
        finally:
            db.close()

    def seal(self, data):
        return self.cipher.encrypt(json.dumps(data, ensure_ascii=False).encode())

    def get(self, identifier):
        with self.connect() as db:
            row = db.execute('SELECT state,expires,payload FROM plans WHERE id=?', (identifier,)).fetchone()
        if not row:
            raise TransferError('Перевод не найден.')
        return row[0], row[1], json.loads(self.cipher.decrypt(row[2]))

    def create(self, data):
        digest = hashlib.sha256(json.dumps([data['source'], data['destination'], data['amount']]).encode()).hexdigest()
        with self.lock, self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute("SELECT id,state,expires FROM plans WHERE fingerprint=? ORDER BY expires DESC", (digest,)).fetchall()
            for identifier, state, expires in previous:
                if state in ('checking', 'posting', 'unknown', 'bank_confirmation'):
                    raise TransferError('Есть перевод с неподтверждённым исходом. Сначала проверьте его в банке; повтор заблокирован.')
                if state in ('prepared', 'confirmed') and expires > time.time():
                    return identifier
            identifier = secrets.token_urlsafe(32)
            db.execute('INSERT INTO plans VALUES (?,?,?,?,?)',
                       (identifier, digest, 'prepared', time.time() + 600, self.seal(data)))
        return identifier

    def claim(self, identifier):
        with self.lock, self.connect() as db:
            result = db.execute("UPDATE plans SET state='checking' WHERE id=? AND state='prepared' AND expires>?",
                                (identifier, time.time()))
            if result.rowcount != 1:
                raise TransferError('Подтверждение уже использовано или истекло.')

    def update(self, identifier, state, data):
        with self.lock, self.connect() as db:
            db.execute('UPDATE plans SET state=?,payload=? WHERE id=?', (state, self.seal(data), identifier))


class OwnTransfers:
    def __init__(self, get_session, store, issuer, maximum='100000'):
        self.get_session, self.store, self.issuer = get_session, store, issuer.rstrip('/')
        self.maximum = money(maximum)
        self.lock = threading.RLock()
        self.last_payment_id = 0

    def quote(self, source, destination, amount):
        session = self.get_session()
        if not isinstance(session, OwnTransferSession):
            raise TransferError('Собственные переводы не включены.')
        if session.ensure_client_session() != 'CLIENT':
            raise TransferError('Банк не подтвердил активный вход. Перевод остановлен.')
        # Не отправлять платёж после незаписанной ротации refresh-токена.
        path = Path(os.environ.get('TBANK_SESSION', Path.home() / '.local/share/tbank-mcp/session.json'))
        if json.loads(path.read_text(encoding='utf-8')).get('refresh_token') != session.refresh_token:
            raise TransferError('Обновлённая сессия не сохранена. Перевод остановлен.')
        accounts = {str(a.get('id')): a for a in session.list_accounts() if isinstance(a, dict)}
        if source == destination or source not in accounts or destination not in accounts:
            raise TransferError('Выберите два разных собственных счёта из list_accounts.')
        for account in (accounts[source], accounts[destination]):
            currency = account.get('currency') or {}
            if (account.get('accountType') not in ('Current', 'Saving') or not isinstance(currency, dict)
                    or currency.get('name') != 'RUB'):
                raise TransferError('Разрешены собственные текущие и накопительные рублёвые счета.')
        source_account = accounts[source]
        if amount > self.maximum or number((source_account.get('moneyAmount') or {}).get('value', 0)) < amount:
            raise TransferError('Недостаточно средств или превышен лимит одного перевода.')
        parameters = {'account': source, 'moneyAmount': float(amount), 'currency': 'RUB',
                      'paymentType': 'Transfer', 'provider': 'transfer-inner',
                      'providerFields': {'bankContract': destination}}
        cards = source_account.get('cards') or []
        card = next((c for c in cards if isinstance(c, dict) and c.get('ucid') and
                     str(c.get('status', '')).lower() not in ('blocked', 'closed')), None)
        if card:
            parameters['ucid'] = str(card['ucid'])
        response = session.own_post('payment_commission', parameters)
        payload = response.get('payload') or {}
        if (response.get('resultCode') != 'OK' or payload.get('providerId') != 'transfer-inner'
                or payload.get('unfinishedFlag') is not False):
            raise TransferError('Банк не завершил проверку перевода. Платёж не отправлен.')
        if number((payload.get('value') or {}).get('value', '-1')) != 0:
            raise TransferError('Банк указал комиссию. Такой перевод не отправляется.')
        total = number((payload.get('total') or {}).get('value', '-1'))
        if total != amount:
            raise TransferError('Банк вернул другую итоговую сумму. Платёж не отправлен.')
        names = [str(accounts[a].get('name') or accounts[a].get('accountType'))[:80] for a in (source, destination)]
        return session, parameters, names

    def prepare(self, source, destination, amount):
        amount = money(amount)
        with self.lock, _MINT_LOCK:
            _, _, names = self.quote(source, destination, amount)
            data = {'source': source, 'destination': destination, 'amount': str(amount), 'names': names}
            identifier = self.store.create(data)
        return {'transfer_id': identifier, **self.status(identifier), 'amount_rub': str(amount), 'commission_rub': '0.00',
                'source': names[0] + ' ····' + source[-4:],
                'destination': names[1] + ' ····' + destination[-4:],
                'message': 'Для prepared вызовите confirm_own_transfer: клиент покажет подтверждение суммы и счетов. Слова агента не заменяют кнопку пользователя.'}

    def status(self, identifier):
        state, expires, _ = self.store.get(identifier)
        return {'status': 'expired' if state == 'prepared' and expires <= time.time() else state,
                'message': 'При unknown/posting/bank_confirmation не создавайте повтор: сначала проверьте банк.'}

    def confirm(self, identifier):
        with self.lock, _MINT_LOCK:
            self.store.claim(identifier)
            _, _, data = self.store.get(identifier)
            try:
                session, parameters, _ = self.quote(data['source'], data['destination'], money(data['amount']))
            except Exception:
                self.store.update(identifier, 'rejected', data)
                raise TransferError('Повторная проверка банка не пройдена. Платёж не отправлен.') from None
            self.last_payment_id = max(int(time.time() * 1000), self.last_payment_id + 1)
            parameters.pop('paymentType', None)
            parameters.update(delayAccepted='false', userPaymentId=str(self.last_payment_id))
            data['user_payment_id'] = parameters['userPaymentId']
            self.store.update(identifier, 'posting', data)
            try:
                result = session.own_post('pay', parameters)
                payload = result.get('payload') or {}
                if result.get('resultCode') == 'OK' and payload.get('paymentId'):
                    state = 'confirmed'
                    data['bank_payment_id'] = str(payload['paymentId'])
                elif result.get('resultCode') == 'WAITING_CONFIRMATION':
                    state = 'bank_confirmation'
                else:
                    state = 'unknown'
                self.store.update(identifier, state, data)
            except Exception:
                self.store.update(identifier, 'unknown', data)
            return self.status(identifier)


def install(mcp, provider, get_session):
    store = PlanStore(Path(provider.store.path).with_name('own-transfers.sqlite'), provider.store.cipher)
    controller = OwnTransfers(get_session, store, provider.issuer, os.environ.get('TBANK_OWN_TRANSFER_MAX_RUB', '100000'))

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True))
    async def prepare_own_transfer(source_account_id: str, destination_account_id: str, amount_rub: str) -> dict:
        """Подготовить RUB-перевод между своими счетами. Деньги НЕ отправляются.

        Затем confirm_own_transfer показывает встроенный диалог клиенту MCP.
        Подтверждение только кнопкой пользователя в ChatGPT/Hermes. При
        неоднозначном названии счёта уточнить выбор. ID берутся из list_accounts.
        """
        try:
            return await run_in_threadpool(controller.prepare, source_account_id, destination_account_id, amount_rub)
        except TransferError as error:
            return {'status': 'rejected', 'message': str(error)}
        except Exception:
            return {'status': 'rejected', 'message': 'Не удалось проверить банк. Перевод не отправлен.'}

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
    def own_transfer_status(transfer_id: str) -> dict:
        """Проверить статус подготовленного перевода. Не отправляет и не повторяет платёж."""
        try:
            return controller.status(transfer_id)
        except TransferError:
            return {'status': 'not_found'}

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True))
    async def confirm_own_transfer(transfer_id: str, ctx: Context) -> dict:
        """Показать пользователю кнопку подтверждения и выполнить подготовленный перевод.

        Сумма и счета зафиксированы в prepare_own_transfer и здесь не меняются.
        Подтверждение только штатным диалогом MCP в ChatGPT/Hermes. Не спрашивать
        код банка или текстовое «да». Отмена, отсутствие диалога, истечение срока
        запрещают отправку. При неизвестном исходе НЕ создавать новый перевод.
        """
        from mcp.server.auth.middleware.auth_context import get_access_token
        from .confirmation import confirm_in_client, confirmation_mode
        access = get_access_token()
        if access is None or OWN_SCOPE not in access.scopes:
            return {'status': 'forbidden', 'message': 'Подключение разрешает только чтение. Переподключите MCP с разрешением собственных переводов.'}
        if confirmation_mode(ctx) is None:
            return {'status': 'not_sent', 'message': 'Клиент не поддерживает встроенное подтверждение MCP. Перевод не отправлен.'}
        try:
            state, expires, data = store.get(transfer_id)
            if state != 'prepared' or expires <= time.time():
                return controller.status(transfer_id)
            # Имена — только подписи. Последние цифры различают одноимённые счета.
            labels = [' '.join(str(n).split()) for n in data['names']]
            message = (f"Перевести {data['amount']} RUB между своими счетами?\n"
                       f"Откуда: {labels[0]} ····{data['source'][-4:]}\n"
                       f"Куда: {labels[1]} ····{data['destination'][-4:]}\n"
                       'Комиссия: 0 RUB. Подтверждение отправит реальный перевод.')
            action = await confirm_in_client(ctx, message)
            if action != 'accept':
                return {'status': 'not_sent', 'message': 'Подтверждение не получено. Перевод не отправлен.'}
            return await run_in_threadpool(controller.confirm, transfer_id)
        except TransferError as error:
            return {'status': 'not_sent', 'message': str(error)}
        except Exception:
            return {'status': 'unknown', 'message': 'Не удалось определить результат. Не повторяйте перевод, проверьте банк.'}

    return controller
