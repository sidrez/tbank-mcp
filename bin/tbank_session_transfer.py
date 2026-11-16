#!/usr/bin/env python3
"""Зашифрованный перенос сессии Т-Банка между Termux и ПК."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import tempfile
import warnings

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b'TBANKS01'


def secret(prompt):
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        value = getpass.getpass(prompt)
    if len(value) < 12:
        raise ValueError('Пароль должен содержать минимум 12 символов.')
    return value.encode('utf-8')


def key(password, salt):
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password)


def validate(raw):
    data = json.loads(raw)
    if not isinstance(data, dict) or not all(isinstance(data.get(k), str) and data[k]
        for k in ('access_token', 'refresh_token', 'mobile_sessionid', 'device_id')):
        raise ValueError('Файл не содержит полной банковской сессии.')


def encrypt(raw, password):
    validate(raw)
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(key(password, salt)).encrypt(nonce, raw, MAGIC)


def decrypt(blob, password):
    if len(blob) < 52 or not blob.startswith(MAGIC):
        raise ValueError('Неверный формат зашифрованного файла.')
    raw = AESGCM(key(password, blob[8:24])).decrypt(blob[24:36], blob[36:], MAGIC)
    validate(raw)
    return raw


def write_new(path, raw):
    if not path.parent.is_dir():
        path.parent.mkdir(parents=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.transfer-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        reservation = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(reservation)
        try:
            os.replace(temporary, path)
        except BaseException:
            os.unlink(path)
            raise
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['export', 'import'])
    parser.add_argument('--input', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    source = args.input or (Path.home() / '.local/share/tbank-mcp/session.json'
                             if args.mode == 'export' else None)
    destination = args.output or (Path.home() / 'storage/downloads/tbank-session.enc'
                                  if args.mode == 'export' else None)
    if source is None or destination is None:
        parser.error('Для импорта нужны --input и --output.')
    try:
        if destination.exists() or destination.is_symlink():
            raise FileExistsError()
        if source.stat().st_size > 1024 * 1024:
            raise ValueError('Слишком большой файл.')
        password = secret('Пароль переноса, минимум 12 символов (скрытый ввод): ')
        if args.mode == 'export':
            if password != secret('Повторите пароль: '):
                raise ValueError('Пароли не совпали.')
            result = encrypt(source.read_bytes(), password)
        else:
            result = decrypt(source.read_bytes(), password)
        write_new(destination, result)
        print(f'Готово: {destination}')
        print('Содержимое сессии не выведено. Исходный файл не изменён.')
        return 0
    except FileExistsError:
        print('Файл назначения уже существует. Он не перезаписан.')
    except (KeyboardInterrupt, EOFError):
        print('\nПеренос отменён.')
    except Exception as error:
        print(f'Перенос не завершён ({type(error).__name__}).')
        print('Проверьте путь, пароль (не менее 12 символов) и совпадение повторного ввода.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
