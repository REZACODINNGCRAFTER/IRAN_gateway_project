# security/otp.py

import random
import string
import time
import hmac
import hashlib
import base64
from typing import Tuple, Optional, Union

class OTPGenerator:
    def __init__(self, digits: int = 6, validity_period: int = 300):
        self.digits = digits
        self.validity_period = validity_period

    def generate_otp(self) -> str:
        return ''.join(random.choices(string.digits, k=self.digits))

    def generate_secret_key(self, length: int = 32) -> str:
        return base64.b32encode(random.randbytes(length)).decode('utf-8')

    def get_hotp_token(self, secret: str, intervals_no: int) -> str:
        key = base64.b32decode(secret, True)
        msg = intervals_no.to_bytes(8, 'big')
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[19] & 15
        token = (int.from_bytes(h[o:o+4], 'big') & 0x7fffffff) % (10 ** self.digits)
        return str(token).zfill(self.digits)

    def get_totp_token(self, secret: str) -> str:
        return self.get_hotp_token(secret, self._current_interval())

    def verify_totp_token(self, token: str, secret: str, window: int = 1) -> bool:
        current_interval = self._current_interval()
        for offset in range(-window, window + 1):
            if self.get_hotp_token(secret, current_interval + offset) == token:
                return True
        return False

    def generate_otp_with_timestamp(self) -> Tuple[str, float]:
        otp = self.generate_otp()
        timestamp = time.time()
        return otp, timestamp

    def is_otp_expired(self, timestamp: float, current_time: Optional[float] = None) -> bool:
        current_time = current_time or time.time()
        return (current_time - timestamp) > self.validity_period

    def _current_interval(self) -> int:
        return int(time.time()) // self.validity_period

    def otp_info(self) -> dict:
        return {
            "digits": self.digits,
            "validity_period": self.validity_period,
            "current_interval": self._current_interval()
        }

    def time_remaining(self, timestamp: float) -> float:
        elapsed = time.time() - timestamp
        return max(0, self.validity_period - elapsed)

    def is_valid_format(self, otp: str) -> bool:
        return otp.isdigit() and len(otp) == self.digits

    def get_expiration_time(self, timestamp: float) -> float:
        return timestamp + self.validity_period

    def describe_token(self, token: str, secret: str) -> dict:
        return {
            "token": token,
            "is_valid_format": self.is_valid_format(token),
            "generated_interval": self._current_interval(),
            "expected_token": self.get_totp_token(secret)
        }

    def remaining_validity(self, timestamp: float, current_time: Optional[float] = None) -> Union[float, None]:
        current_time = current_time or time.time()
        if self.is_otp_expired(timestamp, current_time):
            return None
        return self.validity_period - (current_time - timestamp)

    def regenerate_if_expired(self, timestamp: float, current_time: Optional[float] = None) -> Tuple[str, float]:
        current_time = current_time or time.time()
        if self.is_otp_expired(timestamp, current_time):
            return self.generate_otp_with_timestamp()
        return "", timestamp

# Singleton instance
_otp = OTPGenerator()

def generate_otp():
    return _otp.generate_otp()

def generate_secret_key():
    return _otp.generate_secret_key()

def get_totp_token(secret: str):
    return _otp.get_totp_token(secret)

def verify_totp_token(token: str, secret: str, window: int = 1):
    return _otp.verify_totp_token(token, secret, window)

def generate_otp_with_timestamp():
    return _otp.generate_otp_with_timestamp()

def is_otp_expired(timestamp: float, current_time: Optional[float] = None):
    return _otp.is_otp_expired(timestamp, current_time)

def otp_info():
    return _otp.otp_info()

def time_remaining(timestamp: float):
    return _otp.time_remaining(timestamp)

def is_valid_format(otp: str):
    return _otp.is_valid_format(otp)

def get_expiration_time(timestamp: float):
    return _otp.get_expiration_time(timestamp)

def describe_token(token: str, secret: str):
    return _otp.describe_token(token, secret)

def remaining_validity(timestamp: float, current_time: Optional[float] = None):
    return _otp.remaining_validity(timestamp, current_time)

def regenerate_if_expired(timestamp: float, current_time: Optional[float] = None):
    return _otp.regenerate_if_expired(timestamp, current_time)
