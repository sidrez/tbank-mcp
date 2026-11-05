# Подключение read-only T-Bank MCP к ChatGPT

Инструкция подготовлена 5 ноября 2026 года. Сервер читает данные одного банковского
владельца. Пароль, PIN и SMS вводятся в вашем терминале, а не в ChatGPT.

## 1. Установите именно read-only исходный код

Windows / PowerShell:

```powershell
git clone --branch readonly-chatgpt https://github.com/sidrez/tbank-mcp.git
cd tbank-mcp
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

Если используете архив, распакуйте его и выполните последние две команды в его папке.
Не заменяйте установку на `pip install tbank-mcp`: PyPI содержит исходный проект.

Linux / macOS / VPS:

```bash
git clone --branch readonly-chatgpt https://github.com/sidrez/tbank-mcp.git
cd tbank-mcp
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

На Debian/Ubuntu для создания venv может потребоваться пакет `python3-venv`.
Нужен Python 3.11+. Браузер устанавливать не нужно.

## 2. Выберите отдельное место для сессии

Пример для Windows — выполните в том же PowerShell:

```powershell
$bankData = Join-Path $env:LOCALAPPDATA 'tbank-readonly\account-a'
New-Item -ItemType Directory -Force -Path $bankData | Out-Null
$env:TBANK_SESSION = Join-Path $bankData 'session.json'
$env:TBANK_CA_BUNDLE = Join-Path $bankData 'bundle.pem'
$env:TBANK_TRACE = '0'
.\.venv\Scripts\tbank-mcp-login.exe +7XXXXXXXXXX
```

Замените телефон на свой. Вводите запрошенные секреты только в CLI.
Успех — сообщение «Сессия сохранена». При повторном входе используйте тот же
`TBANK_SESSION`. Не отправляйте `session.json` в чат, GitHub или облачную папку с общим доступом.
На Windows ограничьте доступ к папке своим пользователем через свойства безопасности:
POSIX-режим 0600 сам по себе не заменяет NTFS ACL.

Linux / VPS, в оболочке отдельного пользователя сервиса:

```bash
umask 077
mkdir -p "$HOME/.local/share/tbank-readonly/account-a"
export TBANK_SESSION="$HOME/.local/share/tbank-readonly/account-a/session.json"
export TBANK_CA_BUNDLE="$HOME/.local/share/tbank-readonly/account-a/bundle.pem"
export TBANK_TRACE=0
.venv/bin/tbank-mcp-login +7XXXXXXXXXX
```

`HOME` здесь читается, а не меняется. Сессия не является ограниченным банковским
read-only токеном; ограничения накладывает данный MCP-сервер.

## 3. Проверьте сервер без подключения банка

```powershell
$env:PYTHONUTF8 = '1'
.\.venv\Scripts\python.exe tests/test_readonly.py
```

На Linux: `.venv/bin/python tests/test_readonly.py`.
Ожидается `OK`. Тесты проверяют настоящий MCP handshake, перечень инструментов и
запрет записывающих запросов, используя тестовый HTTP-адаптер.

Для запуска вручную: `.venv\Scripts\tbank-mcp.exe` либо `.venv/bin/tbank-mcp`.
Ожидание ввода без меню нормально: сервер использует stdio. Завершите его Ctrl+C
перед запуском через tunnel-client, который сам создаёт процесс MCP.

## 4. Создайте приватный Secure MCP Tunnel

По [официальной документации OpenAI](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
туннель связывает приватный MCP с ChatGPT исходящим соединением.
Публичный порт для этого проекта не требуется.

1. Откройте Platform → настройки туннелей по ссылке из официального руководства.
2. Выберите свою Platform organization, создайте туннель и сохраните `tunnel_id`.
3. Свяжите его с нужным ChatGPT workspace. Для личного аккаунта используйте
   соответствующую личную организацию; для рабочего — целевой workspace.
4. Для создания нужны Tunnels Read + Manage, для запуска — Read + Use.
5. Создайте runtime API key с нужными правами. Ключ нужен tunnel-client;
   сам банковский MCP не вызывает OpenAI API. Не вставляйте ключ в чат.
6. Скачайте tunnel-client для системы запуска по ссылке в Platform/руководстве,
   поместите исполняемый файл в PATH. При отсутствии Windows-сборки используйте Linux/VPS.

## 5. Свяжите tunnel-client с локальным MCP

В том же PowerShell, где заданы переменные из шага 2:

```powershell
$tunnelSecret = Read-Host 'Runtime API key туннеля' -AsSecureString
$env:CONTROL_PLANE_API_KEY = [System.Net.NetworkCredential]::new('', $tunnelSecret).Password
$mcpProgram = (Resolve-Path '.\.venv\Scripts\tbank-mcp.exe').Path
tunnel-client help quickstart
tunnel-client init --sample sample_mcp_stdio_local --profile tbank-a --tunnel-id tunnel_REPLACE_ME --mcp-command ('"' + $mcpProgram + '"')
tunnel-client doctor --profile tbank-a --explain
tunnel-client run --profile tbank-a
```

Замените `tunnel_REPLACE_ME` полученным ID. Абсолютный путь нужен для запуска из
любой папки. Путь с пробелами заключён в кавычки внутри `--mcp-command`.
Синтаксис сверяйте с `help quickstart` вашей версии tunnel-client.

Linux / VPS, из той же оболочки, где заданы переменные шага 2:

```bash
read -rsp 'Runtime API key туннеля: ' CONTROL_PLANE_API_KEY
echo
export CONTROL_PLANE_API_KEY
tunnel-client help quickstart
tunnel-client init --sample sample_mcp_stdio_local --profile tbank-a --tunnel-id tunnel_REPLACE_ME --mcp-command "$(pwd)/.venv/bin/tbank-mcp"
tunnel-client doctor --profile tbank-a --explain
tunnel-client run --profile tbank-a
```

Оставьте клиент работающим. Он должен наследовать `TBANK_SESSION`,
`TBANK_CA_BUNDLE`, `TBANK_TRACE=0` и ключ. Идентификатор туннеля и пути не являются
банковскими секретами, ключ и файл сессии — являются.

## 6. Добавьте сервер в ChatGPT

Текущий путь подключения описан в [OpenAI: Add custom MCP server](https://developers.openai.com/api/docs/guides/custom-mcp-server).

1. Войдите в нужный аккаунт ChatGPT через браузер.
2. Откройте **Plugins → + → Add custom MCP server**.
3. Название: `Т-Банк — только чтение`.
4. В **Connection** выберите **Tunnel**, затем созданный туннель или его ID.
5. Для этого приватного экземпляра выберите **No authentication**:
   доступ к транспорту ограничивает сам Secure MCP Tunnel. Сервер собственного OAuth не реализует.
6. Подтвердите предупреждение интерфейса и нажмите **Create as a plugin**.
7. Проверьте список: ровно 17 инструментов из README; перевода, оплаты и login в нём нет.
8. Установите полученный плагин в нужном личном/рабочем контексте.
9. В новом чате выберите его через `@` и отправьте:
   «Используй Т-Банк — только чтение. Вызови list_accounts и покажи мои счета и остатки».

Доступ зависит от разрешений аккаунта и workspace. Если пункта добавления нет,
проверьте политику у администратора; наличие подписки само по себе здесь не гарантируется.
В старом интерфейсе пункт может находиться в Settings → Apps → Advanced settings / Create.
Если старый интерфейс принимает только URL и не предлагает Tunnel, не указывайте localhost:
используйте интерфейс с Tunnel. Публичное подключение потребует отдельного HTTPS/OAuth-развёртывания.

Подключение завершено только после успешного чтения в ChatGPT. Локальные тесты
не доказывают успешную авторизацию банка или доступность туннеля в вашем аккаунте.

## 7. Несколько аккаунтов

**Один банковский владелец, несколько ваших ChatGPT-аккаунтов:** подключите тот же
экземпляр в каждом аккаунте и настройте доступ/ассоциации туннеля для каждого
целевого контекста. Все эти аккаунты получат одни и те же банковские данные.
Не передавайте ключ tunnel-client другим пользователям.

**Разные банковские владельцы:** создайте отдельные папки account-a/account-b,
файлы сессий, процессы tunnel-client, профили и туннели. В каждом выполните свой
CLI вход. Не переключайте общий `session.json` между людьми. Этот сервер
не реализует OAuth пользователей ChatGPT и не разделяет данные по ChatGPT identity.

## 8. VPS для постоянной работы

VPS полезен: MCP и tunnel-client продолжают работать после выключения ноутбука.
Схема: ChatGPT → Secure MCP Tunnel → tunnel-client на VPS → stdio MCP → банк.
Для этой схемы публичный домен, nginx и открытый MCP-порт не нужны.

Устанавливайте MCP под отдельным непривилегированным Linux-пользователем.
Вход в банк выполните интерактивно на VPS от имени этого пользователя;
не копируйте банковские секреты в репозиторий Hermes.
Для повторного входа сначала остановите службу, выполните CLI вход, затем запустите её:
это исключает одновременное обновление токена старым процессом.

Пример systemd user unit есть в `deploy/tbank-readonly-tunnel.service.example`.
Он запускает только туннель, а тот — банковский MCP. Подставьте абсолютные пути.
Профиль tunnel-client сначала настройте интерактивно под тем же пользователем.
Runtime key поместите в закрытый файл `~/.config/tbank-readonly/tunnel.env`
строкой `CONTROL_PLANE_API_KEY=...` через редактор, без записи ключа в историю команд.
Каталог должен иметь режим 0700, файл — 0600.

Если VPS управляется через Hermes customizations, используйте его существующий
порядок развёртывания: внешний репозиторий MCP с закреплённым commit, deployment
wiring и registry в Hermes, секреты в Infisical. Не устанавливайте пример unit
вручную поверх управляемой конфигурации. Команды ниже предназначены для отдельной
самостоятельной установки, а не заменяют deployment engine Hermes.

Для вашего Hermes: проект Infisical **Hermes**, environment **prod**, path **/**.
Runtime key туннеля хранится как `TBANK_MCP_TUNNEL_API_KEY`; при запуске он
отображается в требуемую tunnel-client переменную `CONTROL_PLANE_API_KEY`.
Не создавайте пустую запись заранее. При наличии подходящего канонического
ключа переиспользуйте его без дубликата после проверки прав Tunnels Read + Use.
Добавление secret group и формирование scoped-файла в `/run/hermes-secrets`
должны проходить через существующий `hermes-secrets-refresh.service` и deploy.
Постоянный `tunnel.env` на таком VPS создавать не следует.
Пароль банка и SMS/PIN в Infisical для работы MCP не нужны: вход интерактивный.
Ротируемый `session.json` — закрытое runtime state с encrypted backup;
не заменяйте его устаревающей копией из environment variable.

```bash
mkdir -p ~/.config/systemd/user
cp deploy/tbank-readonly-tunnel.service.example ~/.config/systemd/user/tbank-readonly-tunnel.service
# Отредактируйте пути, переменные и профиль в unit перед включением.
systemctl --user daemon-reload
systemctl --user enable --now tbank-readonly-tunnel.service
systemctl --user status tbank-readonly-tunnel.service
```

Для работы после выхода из SSH администратор должен разрешить lingering этому
пользователю (`loginctl enable-linger USER`). Не включайте службу, пока пути,
профиль и права не проверены.

## Если не работает

| Симптом | Что проверить |
| --- | --- |
| Туннеля нет в списке | Целевой ChatGPT workspace/organization, права Read + Use |
| Discovery не проходит | Работающий `tunnel-client run`, `doctor`, абсолютный путь MCP |
| NO_SESSION / SESSION EXPIRED | CLI вход под тем же OS-пользователем и с тем же `TBANK_SESSION` |
| READ_ONLY / READ_ONLY_SECTION | Действие или раздел намеренно запрещены; списка из README достаточно для разрешённых запросов |
| Инструментов больше 17 | Запущен исходный PyPI-пакет или старый сервер; проверьте путь venv и обновите обнаружение инструментов в ChatGPT |
| После перезагрузки нет подключения | systemd unit, доступность ключа и профиля, lingering |

## Источники

- [OpenAI: добавление custom MCP](https://developers.openai.com/api/docs/guides/custom-mcp-server)
- [OpenAI: Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [Исходный проект](https://github.com/icyberdeveloper/tbank-mcp)
