# T-Bank — только чтение

Никогда не запрашивай пароль, PIN или SMS-код в чате. Если сессия недоступна,
пользователь выполняет tbank-mcp-login в своём терминале.

Сначала list_accounts(), затем list_operations(account_id),
spending_categories(account_id) или operations_histogram(account_id).
Карты: list_cards(), card_limits(ucid), card_operations(card_id).
Реквизиты счёта: account_requisites(account_id).
Справки и страховки: bank_documents(), insurance_policies().
Инвестиции: invest_accounts(), invest_portfolio(), invest_operations(), invest_securities().
Дополнительные разделы: get_data(). Справка: flows(). Проверка сессии: session_status().

Учитывай отметки об обрезке/пагинации. Не считай неполный ответ полной историей.
Оплаты, переводы, бронирования, сообщения и любые изменения недоступны.
