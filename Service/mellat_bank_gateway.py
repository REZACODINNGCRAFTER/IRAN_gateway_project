import logging
from typing import Dict, Optional, Any
from django.conf import settings
from django.http import HttpRequest
from django.utils import timezone
from django.core.cache import cache
from zeep import Client, Plugin
from zeep.transports import Transport
import requests

logger = logging.getLogger(__name__)


class SOAPLogPlugin(Plugin):
    """Simple Zeep plugin to log SOAP envelopes"""
    def egress(self, envelope, http_headers, operation, binding_options):
        logger.debug("SOAP Request [%s]: %s", operation.name, envelope)
        return envelope, http_headers

    def ingress(self, envelope, http_headers, operation, binding_options):
        logger.debug("SOAP Response [%s]: %s", operation.name, envelope)
        return envelope, http_headers


class MellatBankGateway:
    WSDL_URL = "https://bpm.shaparak.ir/pgwchannel/services/pgw?wsdl"
    PAYMENT_REDIRECT_URL = "https://bpm.shaparak.ir/pgwchannel/startpay.mellat?RefId={ref_id}"

    STATUS_MESSAGES = {
        "0": "تراکنش موفق",
        "11": "شماره کارت نامعتبر است",
        "12": "موجودی کافی نیست",
        "13": "رمز دوم اشتباه است",
        "14": "تعداد دفعات وارد کردن رمز بیش از حد مجاز است",
        "15": "کارت نامعتبر است",
        "16": "دفعات برداشت وجه بیش از حد مجاز است",
        "17": "کاربر از انجام تراکنش منصرف شده است",
        "18": "تاریخ انقضای کارت گذشته است",
        "19": "مبلغ برداشت وجه بیش از حد مجاز است",
        "21": "پذیرنده نامعتبر است",
        "23": "خطای امنیتی رخ داده است",
        "24": "اطلاعات کاربری پذیرنده نامعتبر است",
        "25": "مبلغ نامعتبر است",
        "31": "پاسخ نامعتبر است",
        "32": "فرمت اطلاعات وارد شده صحیح نمی‌باشد",
        "41": "شماره درخواست تکراری است",
        "42": "تراکنش Sale یافت نشد",
        "43": "قبلا درخواست Verify داده شده است",
        "44": "درخواست Verify یافت نشد",
        "45": "تراکنش Settle شده است",
        "46": "تراکنش Settle نشده است",
        "47": "تراکنش Settle یافت نشد",
        "48": "تراکنش Reverse شده است",
        "51": "تراکنش تکراری است",
        "54": "تراکنش مرجع موجود نیست",
        "55": "تراکنش نامعتبر است",
        "61": "خطا در واریز",
    }

    def __init__(self, terminal_id=None, username=None, password=None):
        self.terminal_id = str(terminal_id or getattr(settings, "MELLAT_TERMINAL_ID", "")).zfill(8)
        self.username = username or getattr(settings, "MELLAT_USERNAME", "")
        self.password = password or getattr(settings, "MELLAT_PASSWORD", "")

        self.client: Optional[Client] = None
        if self.has_required_credentials():
            transport = Transport(timeout=30)
            self.client = Client(self.WSDL_URL, transport=transport, plugins=[SOAPLogPlugin()])

    def has_required_credentials(self) -> bool:
        return bool(self.terminal_id and self.username and self.password)

    def _local_date(self) -> str:
        return timezone.now().strftime("%Y%m%d")

    def _local_time(self) -> str:
        return timezone.now().strftime("%H%M%S")

    def _cache_key(self, prefix: str, order_id: str) -> str:
        return f"mellat_{prefix}_{order_id}"

    # ===================================================================
    # Public API
    # ===================================================================
    def request_payment(self, order_id: str, amount: int, callback_url: str) -> Dict[str, Any]:
        """Step 1 – Request payment and receive RefId"""
        if not self.has_required_credentials() or not self.client:
            return self._error("Gateway credentials missing")

        try:
            response = self.client.service.bpPayRequest(
                terminalId=self.terminal_id,
                userName=self.username,
                userPassword=self.password,
                orderId=order_id,
                amount=amount,
                localDate=self._local_date(),
                localTime=self._local_time(),
                additionalData="",
                callBackUrl=callback_url,
                payerId=0,
            )

            # Mellat returns string like "0,123456789012" or just "41" on error
            if not response or "," not in response:
                return self._error(self.STATUS_MESSAGES.get(response, response or "empty"), response)

            res_code, ref_id = response.split(",", 1)
            if res_code != "0":
                return self._error(self.STATUS_MESSAGES.get(res_code, res_code), res_code)

            return {
                "success": True,
                "ref_id": ref_id.strip(),
                "payment_url": self.PAYMENT_REDIRECT_URL.format(ref_id=ref_id.strip()),
            }

        except Exception as exc:
            logger.exception("bpPayRequest failed")
            return self._error("Connection error", "connection_error")

    def verify_payment(self, order_id: str, sale_reference_id: str) -> Dict[str, Any]:
        return self._call_with_cache(
            "verify", order_id, sale_reference_id,
            self.client.service.bpVerifyRequest
        )

    def settle_payment(self, order_id: str, sale_reference_id: str) -> Dict[str, Any]:
        return self._call_with_cache(
            "settle", order_id, sale_reference_id,
            self.client.service.bpSettleRequest
        )

    def reverse_payment(self, order_id: str, sale_reference_id: str) -> Dict[str, Any]:
        return self._call_with_cache(
            "reverse", order_id, sale_reference_id,
            self.client.service.bpReversalRequest
        )

    def _call_with_cache(self, action: str, order_id: str, sale_reference_id: str, method) -> Dict[str, Any]:
        """Prevents duplicate verify/settle/reverse calls"""
        cache_key = self._cache_key(action, order_id)
        if cache.get(cache_key):
            return {"success": True, "cached": True, "result": "0"}

        try:
            res = method(
                terminalId=self.terminal_id,
                userName=self.username,
                userPassword=self.password,
                orderId=order_id,
                saleOrderId=order_id,
                saleReferenceId=sale_reference_id,
            )
            res = str(res).strip()
            if res != "0":
                return self._error(self.STATUS_MESSAGES.get(res, res), res)

            cache.set(cache_key, True, timeout=60 * 60 * 24)  # 24h safety
            return {"success": True, "result": res}

        except Exception as exc:
            logger.exception("%s failed for order %s", action.capitalize(), order_id)
            return self._error(f"{action.capitalize()} failed")

    # ===================================================================
    # Callback handling
    # ===================================================================
    def handle_callback(self, request: HttpRequest) -> Dict[str, Any]:
        data = self._parse_callback(request)

        res_code = data.get("ResCode")
        if not res_code or res_code != "0":
            msg = self.STATUS_MESSAGES.get(res_code, "خطای ناشناخته")
            self._log_transaction(data, success=False)
            return self._error(msg, res_code)

        order_id = data["SaleOrderId"]
        ref_id = data["SaleReferenceId"]

        # Step 1: Verify
        verify_res = self.verify_payment(order_id, ref_id)
        if not verify_res.get("success"):
            self._log_transaction({**data, "verify": verify_res}, success=False)
            return verify_res

        # Step 2: Settle
        settle_res = self.settle_payment(order_id, ref_id)
        if not settle_res.get("success"):
            # Try to reverse on settle failure
            self.reverse_payment(order_id, ref_id)
            self._log_transaction({**data, "settle": settle_res}, success=False)
            return settle_res

        result = {
            "success": True,
            "order_id": order_id,
            "reference_id": ref_id,
            "card_pan": data.get("CardHolderPan"),
            "amount": data.get("FinalAmount"),
            "status": "paid_and_settled",
        }
        self._log_transaction({**data, **result}, success=True)
        return result

    def _parse_callback(self, request: HttpRequest) -> Dict[str, str]:
        keys = ["RefId", "ResCode", "SaleOrderId", "SaleReferenceId", "CardHolderPan", "FinalAmount"]
        return {k: (request.POST.get(k) or "").strip() for k in keys}

    def _log_transaction(self, data: Dict, success: bool = True) -> None:
        status = "SUCCESS" if success else "FAILURE"
        logger.info("MELLAT | %s | %s", status, json.dumps(data, ensure_ascii=False))

    def _error(self, message: str, code: Optional[str] = None) -> Dict[str, Any]:
        result = {"success": False, "error": message}
        if code:
            result["error_code"] = code
        logger.warning("MELLAT ERROR | %s | Code: %s", message, code or "-")
        return result

    # Test helper
    def simulate_test_payment(self, order_id: str, amount: int) -> Dict[str, Any]:
        ref_id = f"999{hash(order_id) % 1000000:06d}"
        return {
            "success": True,
            "ref_id": ref_id,
            "payment_url": self.PAYMENT_REDIRECT_URL.format(ref_id=ref_id),
            "message": "Test mode – no real transaction",
        }
