# Подключение Т-Банка к ChatGPT напрямую с VPS

Транспорт: HTTPS + Streamable HTTP, авторизация: OAuth 2.1 / PKCE.
OpenAI Platform, ключ OpenAI API и Secure MCP Tunnel для этого способа не нужны.
Применяются обычные ограничения и доступность custom MCP в вашем ChatGPT-аккаунте.

## 1. Сервер

Read-only MCP устанавливается из этого репозитория, не из исходного PyPI-пакета.
В управляемом VPS Hermes код закрепляется в `components/tbank-mcp.yaml`,
а развёртывание проходит через deployment engine с backup.

Команда `tbank-mcp-http` слушает только `127.0.0.1:8954`.
nginx публикует `https://HOST/tbank/mcp` и OAuth discovery-маршруты.
Без OAuth-токена MCP возвращает HTTP 401; tools/list также защищён.
В сервисе задаются переменные:

- `TBANK_MCP_PUBLIC_URL=https://HOST/tbank` — issuer без `/mcp`.
- `TBANK_MCP_OWNER_PASSWORD` — отдельный длинный код разрешения подключения.
- `TBANK_MCP_STATE_KEY` — ключ Fernet для шифрования OAuth state.
- `TBANK_MCP_OAUTH_DB=/var/lib/tbank-readonly/oauth.sqlite`.
- `TBANK_SESSION=/var/lib/tbank-readonly/session.json`.
- `TBANK_CA_BUNDLE=/var/lib/tbank-readonly/bundle.pem`.
- `TBANK_TRACE=0`.

Статические секреты хранятся в **Infisical → Hermes → prod → /**.
В `/run/hermes-secrets/tbank.env` они попадают штатным secret renderer.
Код подключения не является паролем банка. Банковский пароль/PIN/SMS в Infisical
не сохраняются: они нужны только для интерактивного CLI входа.
Сессия банка и зашифрованная OAuth-БД — отдельное закрытое runtime state.

## 2. Ваш вход в банк

Откройте SSH-терминал VPS с интерактивным вводом. Не запускайте вход через чат агента.
Для управляемой установки используйте:

```bash
sudo systemctl stop hermes-tbank-mcp-http.service
sudo -u tbank-mcp env TBANK_SESSION=/var/lib/tbank-readonly/session.json TBANK_CA_BUNDLE=/var/lib/tbank-readonly/bundle.pem /opt/tbank-mcp/venv/bin/tbank-mcp-login +7XXXXXXXXXX
sudo systemctl start hermes-tbank-mcp-http.service
```

Замените телефон на свой. Введите запрошенные SMS/пароль/PIN только в терминале.
Дождитесь сообщения «Сессия сохранена». Секреты в чат не отправляйте.
При истечении сессии повторите эти команды.

## 3. Добавьте MCP в ChatGPT

1. Откройте ChatGPT в браузере под нужным аккаунтом.
2. Откройте **Plugins → + → Add custom MCP server**. В старом интерфейсе —
   **Settings → Apps → Advanced settings → Developer mode**, затем **Create**.
3. Назовите подключение `Т-Банк — только чтение`.
4. Выберите подключение по URL и укажите выданный адрес **`https://HOST/tbank/mcp`**.
5. Authentication: **OAuth**. Если есть выбор регистрации клиента, используйте **DCR**.
   Client ID и Client Secret вручную не нужны: сервер поддерживает регистрацию.
6. Подтвердите добавление. Откроется страница «Т-Банк: только чтение» на вашем VPS.
7. В Infisical откройте `TBANK_MCP_OWNER_PASSWORD`, скопируйте значение в поле
   **«Код подключения»** на странице VPS и нажмите **«Разрешить чтение»**.
   Не вводите здесь пароль банка, PIN или SMS.
8. После возврата в ChatGPT проверьте список: **17 инструментов**, без перевода и оплаты.
9. Установите плагин в нужном личном/рабочем контексте.
10. В новом чате выберите его через `@` и отправьте:
    «Используй Т-Банк — только чтение: вызови list_accounts и покажи счета и остатки».

Если OAuth-интерфейс показывает callback URI, он должен быть на `chatgpt.com`:
`/connector/oauth/{id}` либо `/connector_platform_oauth_redirect`.
Сервер разрешает только эти адреса возврата.

## 4. Несколько аккаунтов

Для нескольких ваших ChatGPT-аккаунтов повторите шаг 3. Каждое подключение получает
отдельную пару токенов; все они читают банковскую сессию одного владельца.
Передача кода подключения другому человеку разрешит ему чтение этих данных.
Для разных банковских владельцев нужны отдельные процессы, сессии, OAuth-БД и секреты.
Многопользовательское разделение банковских данных внутри этого экземпляра отсутствует.

## 5. Проверки

```bash
python tests/test_readonly.py
python tests/test_http_oauth.py
python tests/test_docs_match_code.py
```

Проверяются закрытый список инструментов, HTTP-запрет записи, OAuth discovery,
PKCE, CSRF, отклонение неверного кода, ротация/отзыв токенов и encrypted state.
Успешное подключение подтверждается только чтением счёта из ChatGPT после вашего входа.

Официальные источники:
[добавление custom MCP](https://developers.openai.com/api/docs/guides/custom-mcp-server),
[авторизация MCP](https://developers.openai.com/plugins/build/auth).
