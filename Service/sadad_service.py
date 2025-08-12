import logging
import json
import re
import requests
from typing import Optional, Dict
from hashlib import sha256
from django.conf import settings
from django.http import HttpRequest
from django.utils import timezone

logger = logging.getLogger(__name__)


class SadadService:
    """
    Clean, production-ready Sadad Payment Gateway Integration.
    Documentation: https://sadad.shaparak.ir
    """

    BASE_URL = "https://sadad.shaparak.ir"
    PAYMENT_REQUEST_PATH = "/VPG/api/v0/Request/PaymentRequest"
    PAYMENT_VERIFY_PATH = "/VPG/api/v0/Advice/Verify"
    PAYMENT_GATEWAY_URL = "https://sadad.shaparak.ir/VPG/Purchase"

    IBAN_FULL_NAME = ""
    IBAN_NUMBER = ""

    def __init__(self, merchant_id: Optional[str] = None, terminal_id: Optional[str] = None, terminal_key: Optional[str] = None):
        self.merchant_id = merchant_id or settings.SADAD_MERCHANT_ID
        self.terminal_id = terminal_id or settings.SADAD_TERMINAL_ID
        self.terminal_key = terminal_key or settings.SADAD_TERMINAL_KEY

    def request_payment(self, order_id: str, amount: int, callback_url: str, local_date_time: str, additional_data: Optional[str] = None) -> Dict:
        payload = {
            "MerchantId": self.merchant_id,
            "TerminalId": self.terminal_id,
            "Amount": amount,
            "OrderId": order_id,
            "LocalDateTime": local_date_time,
            "ReturnUrl": callback_url,
            "SignData": self._generate_signature(order_id, amount)
        }
        if additional_data:
            payload["AdditionalData"] = additional_data

        try:
            logger.debug("Sending payment request: %s", payload)
            response = requests.post(
                f"{self.BASE_URL}{self.PAYMENT_REQUEST_PATH}",
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload)
            )
            response.raise_for_status()
            data = response.json()
            data["payment_url"] = self.get_payment_url(data.get("Token"))
            return data
        except requests.RequestException as e:
            logger.exception("Payment request failed.")
            return {"success": False, "error": str(e)}

    def verify_payment(self, token: str) -> Dict:
        payload = {
            "Token": token,
            "SignData": self._generate_signature(token)
        }
        try:
            logger.debug("Verifying payment with token: %s", token)
            response = requests.post(
                f"{self.BASE_URL}{self.PAYMENT_VERIFY_PATH}",
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload)
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.exception("Payment verification failed.")
            return {"success": False, "error": str(e)}

    def _generate_signature(self, *args) -> str:
        raw = "#".join(map(str, args)) + "#" + self.terminal_key
        return sha256(raw.encode()).hexdigest()

    def get_payment_url(self, token: Optional[str]) -> str:
        return f"{self.PAYMENT_GATEWAY_URL}?token={token}" if token else ""

    def handle_callback(self, request: HttpRequest) -> Dict:
        try:
            data = self.parse_callback_data(request)
            token = data.get("token")
            res_code = data.get("ResCode")
            if not token or not res_code:
                raise ValueError("Invalid callback data: missing token or ResCode")

            result = self.verify_payment(token)
            result.update(data)
            result["success"] = self.is_successful_transaction(result)
            return result
        except Exception as e:
            logger.exception("Failed to handle callback.")
            return {"success": False, "error": str(e)}

    def is_successful_transaction(self, response_data: Dict) -> bool:
        return str(response_data.get("ResCode")) == "0" and response_data.get("Status") == 0

    def generate_local_date_time(self) -> str:
        return timezone.now().strftime("%Y/%m/%d %H:%M:%S")

    def parse_callback_data(self, request: HttpRequest) -> Dict:
        expected_fields = ["token", "ResCode", "SystemTraceNo", "OrderId", "Amount", "RetrivalRefNo", "Status"]
        return {field: request.POST.get(field) for field in expected_fields if field in request.POST}

    def log_transaction(self, data: Dict, success: bool = False) -> None:
        status = "SUCCESS" if success else "FAILURE"
        logger.info("Sadad Transaction %s | %s", status, json.dumps(data, ensure_ascii=False))

    def get_status_description(self, status_code: str) -> str:
        descriptions = {
            "0": "Transaction successful",
            "101": "User cancelled the transaction",
            "201": "Insufficient funds",
            "301": "Invalid card number",
            "302": "Incorrect PIN",
        }
        return descriptions.get(status_code, f"Unknown status code: {status_code}")

    def simulate_payment(self, order_id: str, amount: int) -> Dict:
        simulated_token = "test_token_123456"
        return {
            "OrderId": order_id,
            "Amount": amount,
            "Token": simulated_token,
            "payment_url": self.get_payment_url(simulated_token),
            "message": "Simulated payment"
        }

    def extract_token(self, response: Dict) -> Optional[str]:
        return response.get("Token")

    def is_token_valid(self, token: str) -> bool:
        return isinstance(token, str) and len(token) >= 10

    def is_duplicate_order(self, order_id: str) -> bool:
        logger.debug("Checking for duplicate order ID: %s", order_id)
        return False  # Placeholder logic

    def cancel_payment(self, token: str) -> Dict:
        logger.warning("Sadad does not support payment cancellation. Simulating response.")
        return {"Token": token, "Status": "CANCELLED", "Message": "Simulated cancellation."}

    def retry_payment(self, order_id: str, amount: int, callback_url: str, additional_data: Optional[str] = None) -> Dict:
        logger.info("Retrying payment for Order ID: %s", order_id)
        return self.request_payment(order_id, amount, callback_url, self.generate_local_date_time(), additional_data)

    def format_amount(self, amount: int) -> str:
        return f"{amount:,}"

    def anonymize_token(self, token: str) -> str:
        return f"{token[:4]}****{token[-4:]}" if token and len(token) > 8 else token

    def validate_iran_iban(self, iban: str) -> bool:
        return bool(re.fullmatch(r"IR\d{24}", iban.strip().upper()))

    def validate_iran_card(self, card_number: str) -> bool:
        return bool(re.fullmatch(r"603799\d{10}", card_number.strip()))
