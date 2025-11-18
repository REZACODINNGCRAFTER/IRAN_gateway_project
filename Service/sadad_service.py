import logging
import json
from typing import Dict, Optional, Any
from hashlib import sha256
from django.conf import settings
from django.http import HttpRequest
from django.utils import timezone
from django.core.cache import cache
import requests

logger = logging.getLogger(__name__)


class SadadService:
    """
    Production-ready Sadad Payment Gateway (Shaparak PSP) Integration
    Official Documentation: https://sadad.shaparak.ir
    """

    BASE_URL = "https://sadad.shaparak.ir"
    PAYMENT_REQUEST_PATH = "/VPG/api/v0/Request/PaymentRequest"
    PAYMENT_VERIFY_PATH = "/VPG/api/v0/Advice/Verify"
    PAYMENT_GATEWAY_URL = "https://sadad.shaparak.ir/VPG/Purchase"

    RESCODE_DESCRIPTIONS = {
        "0": "تراکنش موفق",
        "-1": "در انتظار پرداخت",
        "3": "پرداخت نشده",
        "101": "کاربر از انجام تراکنش منصرف شده است",
        "201": "موجودی کافی نیست",
        "301": "شماره کارت نامعتبر است",
        "302": "رمز دوم اشتباه است",
        "1000": "خطای داخلی درگاه",
    }

    def __slots__ = ("merchant_id", "terminal_id", "terminal_key")

    def __init__(
        self,
        merchant_id: Optional[str] = None,
        terminal_id: Optional[str] = None,
        terminal_key: Optional[str] = None,
    ):
        self.merchant_id = merchant_id or getattr(settings, "SADAD_MERCHANT_ID", "")
        self.terminal_id = terminal_id or getattr(settings, "SADAD_TERMINAL_ID", "")
        self.terminal_key = terminal_key or getattr(settings, "SADAD_TERMINAL_KEY", "")

    # ------------------------------------------------------------------ #
    # Core Methods
    # ------------------------------------------------------------------ #
    def request_payment(
        self,
        order_id: str,
        amount: int,
        callback_url: str,
        additional_data: Optional[str] = None,
        *,
        local_date_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Request payment token from Sadad"""
        if not all([self.merchant_id, self.terminal_id, self.terminal_key]):
            return self._error("Sadad credentials are missing or incomplete")

        local_date_time = local_date_time or self._now_iso()

        payload = {
            "MerchantId": self.merchant_id,
            "TerminalId": self.terminal_id,
            "Amount": amount,
            "OrderId": str(order_id),
            "LocalDateTime": local_date_time,
            "ReturnUrl": callback_url,
            "SignData": self._sign_payment_request(str(order_id), amount),
        }
        if additional_data:
            payload["AdditionalData"] = additional_data

        try:
            response = requests.post(
                f"{self.BASE_URL}{self.PAYMENT_REQUEST_PATH}",
                json=payload,
                timeout=30,
                headers={"Content-Type": "application/json; charset=utf-8"},
            )
            response.raise_for_status()
            data = response.json()

            res_code = data.get("ResCode")
            if res_code != "0":
                return self._error(self._desc(res_code), res_code)

            token = data.get("Token")
            if not token:
                return self._error("Token not received from gateway")

            data.update({
                "success": True,
                "payment_url": self.get_payment_url(token),
            })
            return data

        except requests.RequestException as e:
            logger.exception("Sadad payment request failed")
            return self._error("Failed to connect to Sadad gateway", "connection_error")

    def verify_payment(self, token: str) -> Dict[str, Any]:
        """Verify and settle payment – idempotent"""
        cache_key = f"sadad_verify_{token}"
        cached = cache.get(cache_key)
        if cached:
            logger.info("Sadad verify skipped (idempotent hit: %s", token[:10])
            return {"success": True, "ResCode": "0", "cached": True}

        payload = {
            "Token": token,
            "SignData": self._sign_verify(token),
        }

        try:
            response = requests.post(
                f"{self.BASE_URL}{self.PAYMENT_VERIFY_PATH}",
                json=payload,
                timeout=30,
            )
            response.raise_for_status()
            result = response.json()

            if result.get("ResCode") == "0":
                cache.set(cache_key, True, timeout=86400)  # 24 hours

            result["success"] = result.get("ResCode") == "0"
            return result

        except requests.RequestException as e:
            logger.exception("Sadad verify request failed")
            return self._error("Verification failed – connection error")

    def handle_callback(self, request: HttpRequest) -> Dict[str, Any]:
        """Main callback entry point – called by Sadad after user payment"""
        data = self._parse_callback(request)

        token = data.get("token")
        res_code = data.get("ResCode")

        if not token:
            return self._error("Missing token in callback")

        if res_code != "0":
            error_msg = self._desc(res_code)
            self._log(data, success=False)
            return {**data, "success": False, "error": error_msg, "ResCode": res_code}

        # Perform verification
        verify_result = self.verify_payment(token)

        if not verify_result.get("success"):
            self._log({**data, "verify_result": verify_result}, success=False)
            return {**data, **verify_result, "success": False}

        # Successful payment
        result = {
            "success": True,
            "order_id": data.get("OrderId"),
            "amount": data.get("Amount"),
            "token": token,
            "reference_id": data.get("RetrievalRefNo"),  # Correct spelling
            "trace_number": data.get("SystemTraceNo"),
            "card_pan_masked": self._mask_card(data.get("CardNumber")),
            "description": self._desc("0"),
        }

        self._log({**data, **result}, success=True)
        return result

    # ------------------------------------------------------------------ #
    # Security & Utilities
    # ------------------------------------------------------------------ #
    def _sign_payment_request(self, order_id: str, amount: int) -> str:
        raw = f"{self.terminal_id};{order_id};{amount}"
        return self._sha256_sign(raw)

    def _sign_verify(self, token: str) -> str:
        return self._sha256_sign(token)

    def _sha256_sign(self, data: str) -> str:
        key_bytes = self.terminal_key.encode("utf-8")
        data_bytes = data.encode("utf-8")
        return sha256(key_bytes + data_bytes).hexdigest()

    def _now_iso(self) -> str:
        return timezone.now().strftime("%Y-%m-%d %H:%M:%S")

    def get_payment_url(self, token: Optional[str]) -> str:
        return f"{self.PAYMENT_GATEWAY_URL}?token={token}" if token else ""

    def _parse_callback(self, request: HttpRequest) -> Dict[str, str]:
        keys = [
            "token",
            "ResCode",
            "OrderId",
            "Amount",
            "SystemTraceNo",
            "RetrievalRefNo",   # Correct field name
            "CardNumber",
            "TerminalId",
            "MerchantId",
        ]
        return {k: (request.POST.get(k) or "").strip() for k in keys if request.POST.get(k)}

    def _desc(self, code: Optional[str]) -> str:
        return self.RESCODE_DESCRIPTIONS.get(code or "", f"کد ناشناخته: {code}")

    def _error(self, message: str, code: Optional[str] = None) -> Dict[str, Any]:
        result = {"success": False, "error": message}
        if code:
            result["ResCode"] = code
        logger.warning("SADAD ERROR | %s | Code: %s", message, code or "-")
        return result

    def _log(self, data: Dict[str, Any], success: bool) -> None:
        safe = data.copy()
        if card := safe.get("CardNumber"):
            safe["CardNumber"] = self._mask_card(card)
        if token := safe.get("token"):
            safe["token"] = token[:8] + "..." + token[-4:] if len(token) > 12 else "****"
        status = "SUCCESS" if success else "FAILURE"
        logger.info("SADAD | %s | %s", status, json.dumps(safe, ensure_ascii=False))

    @staticmethod
    def _mask_card(card: Optional[str]) -> str:
        if not card or len(card) < 10:
            return "****"
        return f"{card[:6]}******{card[-4:]}"

    # ------------------------------------------------------------------ #
    # Test / Debug
    # ------------------------------------------------------------------ #
    def simulate_payment(self, order_id: str, amount: int) -> Dict[str, Any]:
        token = f"TEST_{order_id}_{amount}_{int(timezone.now().timestamp())}"
        return {
            "success": True,
            "ResCode": "0",
            "Token": token,
            "payment_url": self.get_payment_url(token),
            "message": "Simulated Sadad payment – no real charge",
        }
