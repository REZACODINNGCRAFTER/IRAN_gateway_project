import abc
import random
import time
import logging
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger(__name__)


class SMSProviderInterface(abc.ABC):
    """
    Abstract base class for all SMS provider services.
    Defines a standard set of operations to ensure consistency.
    """

    @abc.abstractmethod
    def send_sms(self, phone_number: str, message: str) -> bool:
        """Send a single SMS message."""
        pass

    @abc.abstractmethod
    def send_bulk_sms(self, phone_numbers: List[str], message: str) -> Dict[str, bool]:
        """Send a message to multiple recipients."""
        pass

    @abc.abstractmethod
    def get_credit_balance(self) -> Optional[float]:
        """Return remaining SMS credit balance."""
        pass

    @abc.abstractmethod
    def get_daily_quota_limit(self) -> Optional[int]:
        """Return the daily quota limit for sending SMS."""
        pass

    @abc.abstractmethod
    def get_sent_message_count(self) -> int:
        """Return number of messages sent today."""
        pass

    @abc.abstractmethod
    def reset_daily_quota(self):
        """Reset the counter for daily quota usage."""
        pass

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Return True if provider is operational."""
        pass

    @abc.abstractmethod
    def get_provider_name(self) -> str:
        """Return the name of the provider."""
        pass

    @abc.abstractmethod
    def supports_unicode(self) -> bool:
        """Return True if Unicode is supported."""
        pass

    @abc.abstractmethod
    def validate_phone_number(self, phone_number: str) -> bool:
        """Check if the phone number format is valid."""
        pass

    @abc.abstractmethod
    def estimate_delivery_time(self) -> float:
        """Estimate delivery duration in seconds."""
        pass

    @abc.abstractmethod
    def get_last_delivery_report(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Return the delivery status for a message."""
        pass

    @abc.abstractmethod
    def resend_failed_messages(self) -> Dict[str, bool]:
        """Attempt to resend previously failed messages."""
        pass


class DummySMSProvider(SMSProviderInterface):
    """
    A dummy implementation for testing.
    Mimics sending messages and tracks outcomes.
    """

    def __init__(self):
        self._daily_quota: int = 1000
        self._sent_count: int = 0
        self._supports_unicode: bool = True
        self._delivery_log: Dict[str, Dict[str, Any]] = {}
        self._failed_messages: List[Tuple[str, str]] = []

    def send_sms(self, phone_number: str, message: str) -> bool:
        if not self.validate_phone_number(phone_number):
            logger.warning(f"Invalid phone number: {phone_number}")
            return False

        if self._sent_count >= self._daily_quota:
            logger.warning("Daily SMS quota exceeded.")
            return False

        logger.info(f"Sending SMS to {phone_number}: {message}")
        time.sleep(self.estimate_delivery_time())
        success = random.choices([True, False], weights=[0.8, 0.2])[0]

        message_id = f"msg_{int(time.time() * 1000)}"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        self._delivery_log[message_id] = {
            "phone": phone_number,
            "status": "delivered" if success else "failed",
            "timestamp": timestamp
        }

        if success:
            self._sent_count += 1
        else:
            self._failed_messages.append((phone_number, message))

        return success

    def send_bulk_sms(self, phone_numbers: List[str], message: str) -> Dict[str, bool]:
        return {number: self.send_sms(number, message) for number in phone_numbers}

    def get_credit_balance(self) -> Optional[float]:
        balance = round(random.uniform(0.0, 500.0), 2)
        logger.info(f"Simulated credit balance: {balance}")
        return balance

    def get_daily_quota_limit(self) -> Optional[int]:
        return self._daily_quota

    def get_sent_message_count(self) -> int:
        return self._sent_count

    def reset_daily_quota(self):
        self._sent_count = 0
        logger.info("Daily quota has been reset.")

    def is_available(self) -> bool:
        return True

    def get_provider_name(self) -> str:
        return "DummySMSProvider"

    def supports_unicode(self) -> bool:
        return self._supports_unicode

    def validate_phone_number(self, phone_number: str) -> bool:
        return phone_number.startswith("09") and phone_number.isdigit() and len(phone_number) == 11

    def estimate_delivery_time(self) -> float:
        return round(random.uniform(0.01, 0.1), 2)

    def get_last_delivery_report(self, message_id: str) -> Optional[Dict[str, Any]]:
        return self._delivery_log.get(message_id)

    def resend_failed_messages(self) -> Dict[str, bool]:
        logger.info("Retrying failed messages...")
        results = {}
        for phone, msg in self._failed_messages[:]:
            success = self.send_sms(phone, msg)
            results[phone] = success
            if success:
                self._failed_messages.remove((phone, msg))
        return results
