"""Enforced read-only boundary for MCP (the interactive login CLI is separate).

This policy is deliberately independent of endpoint templates and annotations.
An upstream endpoint change must be reviewed before it is permitted here.
"""
from urllib.parse import parse_qs, urlsplit

import requests

from .client import MobileSession, TbankApiError, SessionExpired, _MINT_LOCK


READONLY_TOOLS = frozenset({
    "session_status", "list_accounts", "list_operations", "spending_categories",
    "operations_histogram", "get_data", "list_cards", "card_limits",
    "card_operations", "account_requisites", "bank_documents",
    "insurance_policies", "invest_accounts", "invest_portfolio",
    "invest_operations", "invest_securities", "flows",
})

# No arbitrary template keys, paths, hosts, payment previews, card credentials,
# identity documents, chat, shopping, bookings or local-file download tools.
READONLY_SECTIONS = {
    "subscriptions": "subscription_all",
    "subscription_bills": "subscription_all_bills",
    "credit_schedule": "credit_payment_schedule",
    "credit_rating": "credit_rating",
    "statements": "statements",
    "invoices": "invoices_to_pay",
    "templates": "payment_templates",
    "cards": "available_cards",
    "loans": "active_loans",
    "autopayments": "autopayments",
    "sbp": "sbp_subscriptions",
    "merchant_subs": "detected_merchant_subscriptions",
    "finhealth_presets": "finhealth_account_presets",
    "finhealth_total": "finhealth_balance_total",
    "finhealth_turnover": "finhealth_balance_turnover",
    "finhealth_invest": "finhealth_invest_turnover",
    "invest_accounts": "investbox_accounts",
    "account_details": "account_details",
    "full_debt_amount": "full_debt_amount",
    "statement_exist": "statement_exist",
}

_MOBILE_GET_PATHS = frozenset({
    "/v1/accounts_light", "/v1/operations", "/v1/operations_histogram",
    "/v1/limits", "/v1/account_group_requisites", "/v1/subscription/all",
    "/v1/subscription/all_bills", "/v1/credit/payment_schedule",
    "/v1/credit_rating", "/v1/statements", "/v1/cm/invoices_to_pay",
    "/v1/templates", "/v1/available_cards", "/v1/active_loans",
    "/v1/autopayments", "/v1/sbp/subscription/list",
    "/subscriptions/merchant/v2/subscriptions",
    "/finhealth/v2/settings/accounts/presets/default",
    "/finhealth/v2/metric/balance/total", "/finhealth/v2/metric/balance/turnover",
    "/finhealth/v2/metric/invest/turnover", "/v1/account_details",
    "/v1/full_debt_amount", "/v1/statement_exist",
})
_READ_ROUTES = frozenset(
    ("GET", "api.t-bank-app.ru", path) for path in _MOBILE_GET_PATHS
) | frozenset({
    ("GET", "www.tbank.ru", "/api/common/v1/session_status"),
    ("GET", "cx-evolution-api.t-bank-app.ru", "/v3/cx-evolution-api/documents/get-document-list"),
    ("GET", "api.tinsurance.ru", "/api/v2/policy/active_with_claims"),
    ("GET", "api-invest.t-bank-app.ru", "/investbox/api/account/all"),
    ("GET", "api-invest-gw.t-bank-app.ru", "/ca-portfolio/api/v1/user/portfolio/statistics"),
    ("GET", "api-invest-gw.t-bank-app.ru", "/ca-operations/api/v1/user/operations"),
    ("GET", "api-invest-gw.t-bank-app.ru", "/invest-portfolio/portfolios/purchased-securities"),
})


def denied():
    raise TbankApiError("READ_ONLY", "Запрос запрещён политикой read-only MCP.")


def check_request(request):
    """Validate the final prepared request, including redirected requests.

    Do not include the URL in errors: it may contain a live session credential.
    Only refresh-token exchange and session ping may POST; neither is a payment.
    """
    url = urlsplit(request.url)
    if (url.scheme != "https" or url.port not in (None, 443)
            or url.username or url.password or url.fragment):
        denied()
    route = (request.method, url.hostname, url.path)
    if route in _READ_ROUTES:
        return
    if route == ("POST", "api.t-bank-app.ru", "/v1/ping"):
        return
    if route == ("POST", "id.t-bank-app.ru", "/auth/token/mobile"):
        body = request.body or ""
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        if (isinstance(body, str)
                and parse_qs(body).get("grant_type") == ["refresh_token"]):
            return
    denied()


class ReadOnlyHTTP(requests.Session):
    def send(self, request, **kwargs):
        check_request(request)
        return super().send(request, **kwargs)


class ReadOnlyMobileSession(MobileSession):
    def __post_init__(self):
        # Never restore a custom transport from a session file.
        self._http = ReadOnlyHTTP()
        super().__post_init__()

    def _fresh_jar(self):
        # New auth/browser jars are unnecessary for these reads. Fail closed.
        denied()

    def ensure_fresh(self, max_age_s=6000):
        # Automatic token rotation is permitted, interactive/silent login is not.
        with _MINT_LOCK:
            if self._needs_mint(max_age_s):
                self.refresh()

    def silent_relogin(self):
        raise SessionExpired("REAUTH_REQUIRED", "Повторите вход локально через tbank-mcp-login.")

    def get_data(self, section, arg="", days=30):
        if section.lower() not in READONLY_SECTIONS:
            raise TbankApiError("READ_ONLY_SECTION", "Разрешены: " + ", ".join(sorted(READONLY_SECTIONS)))
        return super().get_data(section, arg, days)

    def _call_signed(self, *args, **kwargs):
        denied()
