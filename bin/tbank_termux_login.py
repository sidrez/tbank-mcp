#!/usr/bin/env python3
"""Полный локальный вход в Т-Банк через клиент sidrez/tbank-mcp."""
import argparse
from dataclasses import fields
import getpass
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import warnings


class Cancelled(Exception):
    pass


def read_secret(prompt, numeric=False):
    while True:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            value = getpass.getpass(prompt)
        if not value.strip():
            raise Cancelled()
        if numeric:
            value = value.strip()
            if not re.fullmatch(r'[0-9]+', value):
                print('Нужны только цифры. Запрос не отправлен; повторите ввод.')
                continue
        return value


def next_step(message):
    match = re.match(r"^Следующий шаг — '?([\w-]+)'?", str(message))
    if not match:
        raise RuntimeError('Не удалось определить следующий шаг')
    step = match.group(1)
    if step not in {'otp', 'password', 'pin'}:
        raise RuntimeError('Неизвестный шаг; вход остановлен без отправки фактора')
    return step


def credentials_ready(session):
    return bool(session.access_token and session.refresh_token and session.mobile_sessionid)


def save_session(session, output):
    """Формат соответствует загрузчику MCP; runtime-поля не сохраняются."""
    if not credentials_ready(session):
        raise RuntimeError('Банк не выдал полный комплект токенов')
    payload = {field.name: getattr(session, field.name)
               for field in fields(session)
               if field.init and (not field.name.startswith('_') or field.name == '_minted_at')}
    descriptor, temporary = tempfile.mkstemp(prefix='.session-', dir=output.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(payload, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        # Резервируем новое имя, не затрагивая существующую сессию.
        reservation = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(reservation)
        try:
            os.replace(temporary, output)
        except BaseException:
            os.unlink(output)
            raise
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def authenticate(session, api_error, phone, output):
    print('Отправляю один запрос кода. Проверьте SMS и пуши.')
    step = next_step(session.login(phone))
    labels = {'otp': 'Код из SMS/пуша', 'password': 'Пароль интернет-банка',
              'pin': 'PIN приложения, запрошенный банком'}
    seen = set()
    for _ in range(6):
        if step in seen:
            raise RuntimeError('Банк повторил шаг; автоматический повтор остановлен')
        seen.add(step)
        value = read_secret(f'{labels[step]} (скрытый ввод; Enter — отмена): ',
                            numeric=step in {'otp', 'pin'})
        try:
            session.confirm_step(step, value)
        except api_error as error:
            if error.result_code != 'NEXT_STEP':
                raise
            step = next_step(error.message)
            continue
        except Exception:
            # Клиент мог получить токены, а затем потерять соединение на ping.
            if not credentials_ready(session) or getattr(session, '_login_cid', ''):
                raise
            print('Токены получены, но проверка доступности не завершилась.')
        save_session(session, output)
        print(f'Сессия сохранена: {output}')
        print('Файл содержит секреты. Не отправляйте его в чат, почту или GitHub.')
        print('После переноса используйте сессию только на одном устройстве: refresh-токен ротируется.')
        return
    raise RuntimeError('Превышено число этапов входа')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=Path.home() / '.local/share/tbank-mcp/session.json')
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.expanduser().absolute()
    private_root = Path.home().resolve()
    if not output.resolve().is_relative_to(private_root):
        print('Сохраняйте сессию во внутреннем каталоге Termux, внутри $HOME.')
        return 1
    if output.exists() or output.is_symlink():
        print('Файл сессии уже существует. Он не перезаписан; запрос кода не отправлен.')
        return 1
    os.environ['TBANK_TRACE'] = '0'
    session = None
    stage = 'импорт клиента'
    try:
        sys.path.insert(0, str(args.repo.expanduser().resolve()))
        from tbank_mcp.client import MobileSession, TbankApiError, APP_VERSION
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        stage = 'проверка записи файла'
        # Проверяем запись до расходования SMS; os.link в Android может отсутствовать.
        fd, probe = tempfile.mkstemp(prefix='.write-check-', dir=output.parent)
        os.close(fd)
        os.unlink(probe)
        stage = 'ввод телефона'
        print('Все секреты вводятся скрыто: символов и звёздочек не будет.')
        print('Enter без значения отменяет вход. Повторной отправки кода не будет.')
        phone = read_secret('Телефон +7XXXXXXXXXX: ')
        phone = re.sub(r'[ ()-]', '', phone.strip())
        if not re.fullmatch(r'\+7[0-9]{10}', phone):
            print('Неверный формат телефона. Запросы не отправлены.')
            return 1
        stage = 'создание клиента'
        session = MobileSession(mobile_sessionid='', refresh_token='', client_id='gorod-app',
                                client_version='112.0.0', vendor='t_ios',
                                origin='mobile,ib5,loyalty,platform', platform='ios',
                                app_name='mobile', app_version=APP_VERSION)
        stage = 'авторизация и сохранение'
        authenticate(session, TbankApiError, phone, output)
        return 0
    except (Cancelled, KeyboardInterrupt, EOFError):
        print('\nВход отменён. Сессия не сохранена.')
    except getpass.GetPassWarning:
        print('Скрытый ввод недоступен. Запустите скрипт прямо в терминале Termux.')
    except ImportError:
        print('Не хватает клиента или зависимости. Проверьте каталог репозитория и установку requests/cryptography.')
    except Exception as error:
        # Не печатаем текст исключений: он может содержать банковские секреты.
        print(f'Вход или сохранение не завершены ({type(error).__name__}).')
        print(f'Этап: {stage}.')
        code = str(getattr(error, 'result_code', ''))
        if re.fullmatch(r'[A-Za-z0-9_-]{1,64}', code):
            print(f'Код ошибки банка: {code}')
        print('Автоматических повторов нет. Содержимое банковских ответов скрыто.')
    finally:
        if session is not None:
            session._http.close()
    return 1


if __name__ == '__main__':
    sys.exit(main())
