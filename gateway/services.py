"""
Service layer for gateway business logic.
Handles OTP generation/validation, IP blacklist check, login audit logging,
rate limiting, session cleanup, user fingerprint tracking, geolocation enforcement,
CAPTCHA challenge logging, user agent inspection, session hijack detection,
login time validation, and suspicious login pattern alerts.
"""

import logging
from datetime import timedelta
from django.utils import timezone
from django.core.exceptions import PermissionDenied
from django.contrib.auth.models import User
from django.core.cache import cache
from django.conf import settings
from django.http import HttpRequest

from .models import OTPToken, IPBlacklist, LoginAudit

logger = logging.getLogger(__name__)

RATE_LIMIT_KEY = "login-attempts-{ip}"
RATE_LIMIT_WINDOW = getattr(settings, "RATE_LIMIT_WINDOW", 300)  # seconds
RATE_LIMIT_THRESHOLD = getattr(settings, "RATE_LIMIT_THRESHOLD", 5)


def generate_otp_token(user: User) -> OTPToken:
    token = OTPToken.objects.create(user=user)
    logger.info(f"OTP token generated for user {user.username}")
    return token


def validate_otp_token(user: User, token: str) -> bool:
    match = OTPToken.objects.filter(user=user, token=token, is_used=False).first()
    if match and not match.is_expired():
        match.mark_used()
        logger.info(f"OTP token validated for user {user.username}")
        return True
    logger.warning(f"Failed OTP validation for user {user.username}")
    return False


def check_ip_blacklist(ip_address: str):
    if IPBlacklist.objects.filter(ip_address=ip_address).exists():
        logger.warning(f"Blocked login attempt from blacklisted IP {ip_address}")
        raise PermissionDenied("Your IP address has been blacklisted.")


def log_login_attempt(user: User, ip_address: str, success: bool):
    LoginAudit.objects.create(user=user, ip_address=ip_address, success=success)
    status = "SUCCESS" if success else "FAILURE"
    logger.info(f"Login {status} for {user.username} from {ip_address}")


def apply_rate_limiting(ip_address: str):
    key = RATE_LIMIT_KEY.format(ip=ip_address)
    attempts = cache.get(key, 0) + 1
    cache.set(key, attempts, RATE_LIMIT_WINDOW)
    if attempts > RATE_LIMIT_THRESHOLD:
        logger.warning(f"Rate limit exceeded for IP {ip_address}: {attempts} attempts")
        raise PermissionDenied("Too many login attempts. Please try again later.")


def reset_rate_limit(ip_address: str):
    key = RATE_LIMIT_KEY.format(ip=ip_address)
    cache.delete(key)


def cleanup_expired_otps():
    expired_tokens = OTPToken.objects.filter(created_at__lt=timezone.now() - timedelta(minutes=10), is_used=False)
    count = expired_tokens.count()
    expired_tokens.delete()
    logger.info(f"Cleaned up {count} expired OTP tokens.")


def track_user_fingerprint(user: User, fingerprint: str):
    logger.info(f"Fingerprint recorded for user {user.username}: {fingerprint}")
    return True


def enforce_geolocation_policy(country_code: str):
    restricted = getattr(settings, "GATEWAY_FORBIDDEN_COUNTRIES", [])
    if country_code.upper() in restricted:
        logger.warning(f"Access denied from restricted country: {country_code}")
        raise PermissionDenied("Access from your region is restricted.")


def log_captcha_event(user: User, ip_address: str, result: str):
    logger.info(f"CAPTCHA {result.upper()} for {user.username} from {ip_address}")


def inspect_user_agent(request: HttpRequest):
    user_agent = request.META.get("HTTP_USER_AGENT", "unknown")
    logger.info(f"User-Agent for session {request.session.session_key}: {user_agent}")
    return user_agent


def detect_session_hijack(request: HttpRequest, stored_fingerprint: str) -> bool:
    current_fingerprint = request.META.get("HTTP_USER_AGENT", "") + request.META.get("REMOTE_ADDR", "")
    if current_fingerprint != stored_fingerprint:
        logger.warning("Possible session hijack attempt detected.")
        return True
    return False


def validate_login_time(user: User) -> bool:
    now_hour = timezone.now().hour
    allowed_hours = getattr(settings, "GATEWAY_ALLOWED_HOURS", range(0, 24))
    if now_hour not in allowed_hours:
        logger.warning(f"Login outside of allowed hours for {user.username}: hour={now_hour}")
        raise PermissionDenied("Login not allowed at this time.")
    return True


def alert_on_suspicious_pattern(user: User, ip_address: str):
    key = f"suspicious-{user.username}-{ip_address}"
    attempts = cache.get(key, 0) + 1
    cache.set(key, attempts, 600)
    if attempts > 3:
        logger.critical(f"Suspicious login pattern detected for {user.username} from {ip_address}")
        # Optional: Trigger external alert system
