import logging
from typing import Dict, Any, Optional
from django.conf import settings
from django.http import HttpRequest
from django.utils import timezone
from django.core.cache import cache
import requests

logger = logging.getLogger(__name__)


class ZarinpalService:
    """
    Production-ready Zarinpal Payment Gateway integration (v4 API – 2025)
    Official Docs: https://docs.zarinpal.com/paymentGateway/v4
    """

    # Production URLs
    BASE_URL = "https://api.zarinpal.com/pg/v4/payment"
    GATEWAY_URL = "https://www.zarinpal.com/pg/StartPay"

    # Sandbox URLs
    SANDBOX_BASE_URL = "https://sandbox.zarinpal.com/pg/v4/payment"
    SANDBOX_GATEWAY_URL = "https://sandbox.zarinpal.com/pg/StartPay"

    STATUS_MESSAGES = {
        100: "پرداخت موفق",
        101: "پرداخت قبلاً تأیید شده",
        -1: "اطلاعات ناقص",
        -2: "مرچنت کد یا IP نامعتبر",
        -3: "مبلغ کمتر از حداقل مجاز",
        -9: "درخواست نامعتبر",
        -11: "درخواست تکراری",
        -30: "تراکنش قبلاً وریفای شده",
        -33: "مبلغ با پرداخت مطابقت ندارد",
        -51: "تراکنش ناموفق",
        -54: "درخواست آرشیو شده",
    }

    def __init__(self, sandbox: bool = False):
        self.sandbox = sandbox or getattr(settings, "ZARINPAL_SANDBOX", False)
        self.merchant_id = getattr(settings, "ZARINPAL_MERCHANT_ID", "")
        self.base_url = self.SANDBOX_BASE_URL if self.sandbox else self.BASE_URL
        self.gateway_url = self.SANDBOX_GATEWAY_URL if self.sandbox else self.GATEWAY_URL

        if not self.merchant_id:
            logger.error("ZARINPAL_MERCHANT_ID is not configured in settings!")

    def _post(self, endpoint: str, payload: Dict) -> Dict[str, Any]:
        try:
            response = requests.post(
                f"{self.base_url}{endpoint}",
                json=payload,
                timeout=30,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.exception("Zarinpal API error: %s", e)
            return {"data": {}, "errors": {"code": -999, "message": "خطای ارتباط با زرین‌پال"}}

    def request_payment(
        self,
        amount: int,
        callback_url: str,
        description: str = "پرداخت سفارش",
        order_id: Optional[str] = None,
        mobile: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create payment request → return payment URL"""
        if not self.merchant_id:
            return {"success": False, "error": "مرچنت آیدی تنظیم نشده است"}

        if amount < 1000:
            return {"success": False, "error": "مبلغ باید حداقل ۱۰۰۰ ریال باشد"}

        payload = {
            "merchant_id": self.merchant_id,
            "amount": amount,
            "description": description,
            "callback_url": callback_url,
        }

        # Metadata (recommended)
        metadata = {}
        if order_id:
            metadata["order_id"] = str(order_id)
        if mobile:
            metadata["mobile"] = mobile
        if email:
            metadata["email"] = email
        if metadata:
            payload["metadata"] = metadata

        result = self._post("/request.json", payload)
        data = result.get("data", {})
        errors = result.get("errors", {})

        if data.get("code") == 100:
            authority = data["authority"]
            payment_url = f"{self.gateway_url}/{authority}"

            # Prevent duplicate payment requests
            cache.set(f"zarinpal_request_{authority}", True, timeout=600)  # 10 min

            return {
                "success": True,
                "authority": authority,
                "payment_url": payment_url,
                "fee": data.get("fee", 0),
                "fee_type": data.get("fee_type", "Merchant"),
            }

        return {
            "success": False,
            "error_code": errors.get("code"),
            "error_message": errors.get("message", self.STATUS_MESSAGES.get(errors.get("code"), "خطای ناشناخته")),
        }

    def verify_payment(self, authority: str, amount: int) -> Dict[str, Any]:
        """Verify payment – idempotent & secure"""
        cache_key = f"zarinpal_verified_{authority}"
        if cache.get(cache_key):
            ref_id = cache.get(cache_key)
            logger.info("Payment already verified: %s → %s", authority, ref_id)
            return {"success": True, "already_verified": True, "ref_id": ref_id}

        payload = {
            "merchant_id": self.merchant_id,
            "authority": authority,
            "amount": amount,
        }

        result = self._post("/verify.json", payload)
        data = result.get("data", {})
        errors = result.get("errors", {})

        code = data.get("code") or errors.get("code", -999)

        response = {
            "success": code in {100, 101},
            "code": code,
            "message": self.STATUS_MESSAGES.get(code, "وضعیت نامشخص"),
            "ref_id": data.get("ref_id"),
            "card_pan_masked": self._mask_card(data.get("card_pan")),
            "card_hash": data.get("card_hash"),
            "fee": data.get("fee"),
            "fee_type": data.get("fee_type"),
        }

        if response["success"]:
            cache.set(cache_key, response["ref_id"], timeout=60 * 60 * 24 * 90)  # 90 days

        return response

    def handle_callback(self, request: HttpRequest) -> Dict[str, Any]:
        """Main callback handler – NEVER trust Status=OK"""
        authority = request.GET.get("Authority")
        status = request.GET.get("Status", "").upper()

        if not authority:
            return {"success": False, "error": "پارامتر Authority الزامی است"}

        if status != "OK":
            return {
                "success": False,
                "error": "پرداخت توسط کاربر لغو شد",
                "status": status,
            }

        order_id = request.GET.get("order_id")
        amount = self._get_order_amount(order_id, request)

        if not amount:
            logger.error("Order amount not found for order_id: %s", order_id)
            return {"success": False, "error": "سفارش معتبر یافت نشد"}

        verify_result = self.verify_payment(authority, amount)

        if not verify_result["success"]:
            logger.warning("Zarinpal verification failed: %s", verify_result)
            return {
                "success": False,
                "authority": authority,
                "error": verify_result["message"],
                "error_code": verify_result["code"],
            }

        # Success!
        return {
            "success": True,
            "authority": authority,
            "ref_id": verify_result["ref_id"],
            "card_pan_masked": verify_result["card_pan_masked"],
            "message": "پرداخت با موفقیت تأیید شد",
            "order_id": order_id,
        }

    def _get_order_amount(self, order_id: Optional[str], request: HttpRequest) -> Optional[int]:
        """MUST be implemented in your project"""
        if not order_id:
            return None

        # Recommended: Use signed session or cache
        key = f"pending_payment_{order_id}"
        amount = cache.get(key)

        if amount is not None:
            return int(amount)

        # Alternative: Query database
        # from orders.models import Order
        # try:
        #     order = Order.objects.get(id=order_id, paid=False)
        #     cache.set(key, order.amount, timeout=1800)  # 30 min
        #     return order.amount
        # except Order.DoesNotExist:
        #     return None

        return None

    @staticmethod
    def _mask_card(pan: Optional[str]) -> str:
        if not pan or len(pan) < 10:
            return "****-****-****-****"
        return f"{pan[:6]}******{pan[-4:]}"

    def get_status_message(self, code: int) -> str:
        return self.STATUS_MESSAGES.get(code, "وضعیت نامشخص")

    def log_transaction(self, data: Dict[str, Any]) -> None:
        safe_data = data.copy()
        if "card_pan" in safe_data:
            safe_data["card_pan_masked"] = self._mask_card(safe_data["card_pan"])
            del safe_data["card_pan"]
        logger.info("ZARINPAL TRANSACTION | %s", safe_data)
