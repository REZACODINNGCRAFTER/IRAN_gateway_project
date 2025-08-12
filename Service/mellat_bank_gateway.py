import logging
import json
from typing import Dict, Optional, Any
from django.conf import settings
from django.http import HttpRequest
from django.utils import timezone

logger = logging.getLogger(__name__)


class MellatBankGateway:
    BASE_URL = "https://bpm.shaparak.ir/pgwchannel/services/pgw?wsdl"
    PAYMENT_REDIRECT_URL = "https://bpm.shaparak.ir/pgwchannel/startpay.mellat?RefId={ref_id}"
    GATEWAY_IBAN = ""

    def __init__(self, terminal_id=None, username=None, password=None):
        self.terminal_id = terminal_id or settings.MELLAT_TERMINAL_ID
        self.username = username or settings.MELLAT_USERNAME
        self.password = password or settings.MELLAT_PASSWORD

    def get_gateway_name(self) -> str:
        return "MellatBank"

    def get_gateway_iban(self) -> str:
        return self.GATEWAY_IBAN

    def build_payment_url(self, ref_id: str) -> str:
        return self.PAYMENT_REDIRECT_URL.format(ref_id=ref_id)

    def generate_transaction_id(self, order_id: str) -> str:
        return f"{order_id}-{timezone.now().strftime('%Y%m%d%H%M%S')}"

    def generate_local_datetime(self) -> str:
        return timezone.now().strftime("%Y/%m/%d %H:%M:%S")

    def format_amount(self, amount: int) -> str:
        return f"{amount:,}"

    def has_required_credentials(self) -> bool:
        return all([self.terminal_id, self.username, self.password])

    def request_payment(self, order_id: str, amount: int, callback_url: str) -> Dict:
        if not self.has_required_credentials():
            return self._handle_error("Missing credentials", Exception("Incomplete configuration"))

        payload = self._build_payment_payload(order_id, amount, callback_url)
        response = self._simulate_gateway_response("request")
        ref_id = response.get("refId")
        return {
            "ref_id": ref_id,
            "payment_url": self.build_payment_url(ref_id)
        }

    def verify_payment(self, sale_order_id: str, sale_reference_id: str) -> Dict:
        payload = self._build_verification_payload(sale_order_id, sale_reference_id)
        return self._simulate_gateway_response("verify")

    def reverse_payment(self, sale_order_id: str, sale_reference_id: str) -> Dict:
        payload = self._build_verification_payload(sale_order_id, sale_reference_id)
        return self._simulate_gateway_response("reverse")

    def cancel_transaction(self, order_id: str) -> Dict:
        return self._simulate_gateway_response("cancel")

    def handle_callback(self, request: HttpRequest) -> Dict:
        try:
            data = self._parse_callback(request)
            if not self._validate_callback_fields(data):
                raise ValueError("Missing callback data")

            if data.get("ResCode") != "0":
                raise ValueError(self.get_status_message(data.get("ResCode")))

            result = self.verify_payment(data["SaleOrderId"], data["SaleReferenceId"])
            result.update(data)
            self._log_transaction(result, success=True)
            return result
        except Exception as e:
            self._log_transaction(locals().get("data", {}), success=False)
            return self._handle_error("Callback failed", e)

    def get_status_message(self, code: Optional[str]) -> str:
        return {
            "0": "Transaction successful",
            "11": "Invalid card number",
            "12": "Insufficient funds",
            "13": "Incorrect PIN",
            "17": "User cancelled transaction",
            "23": "Invalid expiration date",
        }.get(code, f"Unknown error code: {code}")

    def build_callback_payload(self, request: HttpRequest) -> Dict:
        data = self._parse_callback(request)
        data.update({
            "timestamp": self.generate_local_datetime(),
            "gateway": self.get_gateway_name()
        })
        return data

    def summarize_transaction(self, data: Dict) -> str:
        ref = data.get("SaleReferenceId", "")
        masked_ref = ref[:4] + "****" + ref[-4:] if len(ref) > 8 else ref
        amount = self.format_amount(int(data.get("FinalAmount", 0)))
        return f"Order ID: {data.get('SaleOrderId')} | Ref: {masked_ref} | Amount: {amount}"

    def get_callback_data_as_json(self, request: HttpRequest) -> str:
        return json.dumps(self._parse_callback(request), ensure_ascii=False, indent=2)

    def is_valid_ref_id(self, ref_id: str) -> bool:
        return ref_id.isdigit() and len(ref_id) >= 6

    def is_successful_transaction(self, data: Dict) -> bool:
        return data.get("result") == "0"

    def extract_error_code(self, response: Dict[str, Any]) -> Optional[str]:
        return response.get("errorCode") or response.get("ResCode")

    def extract_ref_id(self, response: Dict[str, Any]) -> Optional[str]:
        return response.get("refId")

    def notify_admin(self, message: str, data: Optional[Dict] = None) -> None:
        logger.warning("ADMIN NOTICE | %s | DATA: %s", message, json.dumps(data or {}))

    def retry_payment(self, order_id: str, amount: int, callback_url: str) -> Dict:
        return self.request_payment(order_id, amount, callback_url)

    def simulate_test_payment(self, order_id: str, amount: int) -> Dict:
        test_ref = "TEST123456"
        return {
            "ref_id": test_ref,
            "payment_url": self.build_payment_url(test_ref),
            "OrderId": order_id,
            "Amount": amount,
            "message": "Simulated test payment."
        }

    def _parse_callback(self, request: HttpRequest) -> Dict:
        try:
            return {key: request.POST.get(key) for key in (
                "RefId", "ResCode", "SaleOrderId", "SaleReferenceId",
                "CardHolderPan", "FinalAmount", "HashedCardNumber"
            )}
        except Exception as e:
            logger.error("Failed to parse callback: %s", e)
            return {}

    def _validate_callback_fields(self, data: Dict) -> bool:
        required_keys = ("SaleOrderId", "SaleReferenceId")
        return all(data.get(k) for k in required_keys)

    def _log_transaction(self, data: Dict, success: bool = True) -> None:
        status = "SUCCESS" if success else "FAILURE"
        logger.info("%s | Transaction Data: %s", status, json.dumps(data, ensure_ascii=False))

    def _handle_error(self, msg: str, exception: Exception) -> Dict:
        logger.error("%s: %s", msg, exception)
        return {"success": False, "error": str(exception)}

    def _build_payment_payload(self, order_id: str, amount: int, callback_url: str) -> Dict:
        now = timezone.now()
        return {
            "terminalId": self.terminal_id,
            "userName": self.username,
            "userPassword": self.password,
            "orderId": order_id,
            "amount": amount,
            "localDate": now.strftime("%Y%m%d"),
            "localTime": now.strftime("%H%M%S"),
            "callBackUrl": callback_url,
            "payerId": 0,
        }

    def _build_verification_payload(self, sale_order_id: str, sale_reference_id: str) -> Dict:
        return {
            "terminalId": self.terminal_id,
            "userName": self.username,
            "userPassword": self.password,
            "orderId": sale_order_id,
            "saleReferenceId": sale_reference_id,
        }

    def _simulate_gateway_response(self, action: str) -> Dict[str, Any]:
        mock_responses = {
            "request": {"result": "0", "refId": "123456789"},
            "verify": {"result": "0"},
            "cancel": {"result": "0", "message": "Transaction cancelled"},
            "reverse": {"result": "0", "message": "Transaction reversed"},
        }
        return mock_responses.get(action, {"result": "-1"})
