import requests
import json
import logging
from typing import Optional, Dict, Any
from django.conf import settings
from django.http import HttpRequest
from django.utils import timezone

logger = logging.getLogger(__name__)


class ZarinpalService:
    """
    Clean and maintainable integration with Zarinpal Payment Gateway.
    Documentation: https://docs.zarinpal.com/paymentGateway
    """

    BASE_URL = "https://api.zarinpal.com/pg/v4/payment"
    START_PAYMENT_PATH = "/request.json"
    VERIFY_PAYMENT_PATH = "/verify.json"
    GATEWAY_URL = "https://www.zarinpal.com/pg/StartPay"
    MERCHANT_ID = settings.ZARINPAL_MERCHANT_ID

    def request_payment(self, order_id: str, amount: int, callback_url: str, description: str = "") -> Dict[str, Any]:
        payload = {
            "merchant_id": self.MERCHANT_ID,
            "amount": amount,
            "callback_url": callback_url,
            "description": description or f"Payment for order #{order_id}",
            "metadata": {"order_id": order_id},
        }
        logger.debug("Sending payment request", extra=payload)
        try:
            response = requests.post(f"{self.BASE_URL}{self.START_PAYMENT_PATH}", json=payload)
            response.raise_for_status()
            data = response.json().get("data", {})
            return {
                **data,
                "payment_url": f"{self.GATEWAY_URL}/{data.get('authority')}"
            }
        except requests.RequestException as e:
            logger.exception("Zarinpal payment request failed")
            return {"success": False, "error": str(e)}

    def verify_payment(self, authority: str, amount: int) -> Dict[str, Any]:
        payload = {
            "merchant_id": self.MERCHANT_ID,
            "amount": amount,
            "authority": authority
        }
        logger.debug("Sending payment verification", extra=payload)
        try:
            response = requests.post(f"{self.BASE_URL}{self.VERIFY_PAYMENT_PATH}", json=payload)
            response.raise_for_status()
            return response.json().get("data", {})
        except requests.RequestException as e:
            logger.exception("Zarinpal payment verification failed")
            return {"success": False, "error": str(e)}

    def handle_callback(self, request: HttpRequest) -> Dict[str, Any]:
        authority = request.GET.get("Authority")
        status = request.GET.get("Status")
        if not authority or not status:
            logger.warning("Missing callback parameters", extra=request.GET.dict())
            return {"success": False, "error": "Missing Authority or Status."}
        return {
            "authority": authority,
            "status": status,
            "success": status.upper() == "OK"
        }

    def format_verification_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ref_id": data.get("ref_id"),
            "card_pan": self.mask_card_pan(data.get("card_pan")),
            "fee_type": data.get("fee_type"),
            "fee": data.get("fee"),
            "status": data.get("code"),
            "message": data.get("message"),
        }

    def is_successful_payment(self, data: Dict[str, Any]) -> bool:
        return data.get("code") == 100

    def extract_error_message(self, data: Dict[str, Any]) -> Optional[str]:
        if isinstance(data.get("errors"), dict):
            return data["errors"].get("message")
        return data.get("message")

    def get_status_message(self, code: Optional[int]) -> str:
        return {
            100: "Payment successful.",
            101: "Payment already verified.",
            -1: "Incomplete information.",
            -2: "Invalid merchant ID or IP.",
            -3: "Amount below minimum.",
        }.get(code, "Unknown status code.")

    def summarize_transaction(self, data: Dict[str, Any]) -> str:
        return (
            f"Transaction: {data.get('ref_id')} | "
            f"Card: {self.mask_card_pan(data.get('card_pan'))} | "
            f"Amount: {data.get('fee')} {data.get('fee_type')} | "
            f"Status: {data.get('code')} - {data.get('message')}"
        )

    def normalize_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        code = data.get("code")
        return {
            "reference_id": data.get("ref_id"),
            "masked_card": self.mask_card_pan(data.get("card_pan")),
            "status_code": code,
            "message": self.get_status_message(code),
            "timestamp": timezone.now().isoformat()
        }

    def create_audit_log(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "action": action,
            "timestamp": timezone.now().isoformat(),
            "payload": payload
        }

    def should_retry(self, code: Optional[int]) -> bool:
        return code in {-1, -3}

    def get_callback_payload(self, request: HttpRequest) -> Dict[str, Optional[str]]:
        return {
            "authority": request.GET.get("Authority"),
            "status": request.GET.get("Status"),
            "order_id": request.GET.get("order_id")
        }

    def attach_client_metadata(self, data: Dict[str, Any], user_agent: str, ip: str) -> Dict[str, Any]:
        return {
            **data,
            "user_agent": user_agent,
            "ip_address": ip
        }

    def log_transaction(self, data: Dict[str, Any]) -> None:
        logger.info("Transaction log", extra={"transaction": data})

    def mask_card_pan(self, pan: Optional[str]) -> str:
        if not pan or len(pan) < 6:
            return "****-****-****-****"
        return f"{pan[:6]}-****-****-{pan[-4:]}"
