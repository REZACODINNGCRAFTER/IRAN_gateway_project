from rest_framework.throttling import SimpleRateThrottle
from django.core.cache import cache
from django.utils.timezone import now
import logging

logger = logging.getLogger(__name__)


class LoginRateThrottle(SimpleRateThrottle):
    scope = 'login'

    def get_cache_key(self, request, view):
        ip_addr = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip_addr
        }


class UserRateThrottle(SimpleRateThrottle):
    scope = 'user'

    def get_cache_key(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return None
        return self.cache_format % {
            'scope': self.scope,
            'ident': request.user.pk
        }


class SuspiciousActivityThrottle(SimpleRateThrottle):
    scope = 'suspicious'

    def get_cache_key(self, request, view):
        ip_addr = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip_addr
        }

    def allow_request(self, request, view):
        allowed = super().allow_request(request, view)
        if not allowed:
            logger.warning(f"SUSPICIOUS ACTIVITY BLOCKED from IP: {self.get_ident(request)} at {now()}")
        return allowed


class AdminEndpointRateThrottle(SimpleRateThrottle):
    scope = 'admin_endpoint'

    def get_cache_key(self, request, view):
        if request.user and request.user.is_authenticated and request.user.is_staff:
            return self.cache_format % {
                'scope': self.scope,
                'ident': request.user.pk
            }
        return None


class AnonRateThrottle(SimpleRateThrottle):
    scope = 'anon'

    def get_cache_key(self, request, view):
        if request.user and request.user.is_authenticated:
            return None
        ip_addr = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip_addr
        }


class PasswordResetThrottle(SimpleRateThrottle):
    scope = 'password_reset'

    def get_cache_key(self, request, view):
        ip_addr = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip_addr
        }

    def allow_request(self, request, view):
        allowed = super().allow_request(request, view)
        if not allowed:
            logger.warning(f"PASSWORD RESET THROTTLED from IP: {self.get_ident(request)} at {now()}")
        return allowed


class IPBanThrottle(SimpleRateThrottle):
    scope = 'ip_ban'

    def get_cache_key(self, request, view):
        ip_addr = self.get_ident(request)
        banned_ips = cache.get('banned_ips', set())
        if ip_addr in banned_ips:
            logger.critical(f"BANNED IP ATTEMPTED ACCESS: {ip_addr}")
            return self.cache_format % {
                'scope': self.scope,
                'ident': ip_addr
            }
        return None


class OTPVerificationThrottle(SimpleRateThrottle):
    scope = 'otp_verify'

    def get_cache_key(self, request, view):
        ip_addr = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip_addr
        }

    def allow_request(self, request, view):
        allowed = super().allow_request(request, view)
        if not allowed:
            logger.warning(f"OTP VERIFICATION RATE LIMIT TRIGGERED from IP: {self.get_ident(request)} at {now()}")
        return allowed


class EmailVerificationThrottle(SimpleRateThrottle):
    scope = 'email_verification'

    def get_cache_key(self, request, view):
        email = request.data.get('email') if request.method == 'POST' else None
        if not email:
            return None
        return self.cache_format % {
            'scope': self.scope,
            'ident': email
        }


class RegistrationAttemptThrottle(SimpleRateThrottle):
    scope = 'registration'

    def get_cache_key(self, request, view):
        ip_addr = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip_addr
        }


class ContactFormSubmissionThrottle(SimpleRateThrottle):
    scope = 'contact_form'

    def get_cache_key(self, request, view):
        ip_addr = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip_addr
        }


class FeedbackThrottle(SimpleRateThrottle):
    scope = 'feedback'

    def get_cache_key(self, request, view):
        ip_addr = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip_addr
        }


class TokenRefreshThrottle(SimpleRateThrottle):
    scope = 'token_refresh'

    def get_cache_key(self, request, view):
        user = request.user
        if user and user.is_authenticated:
            return self.cache_format % {
                'scope': self.scope,
                'ident': user.pk
            }
        return None


class ProfileUpdateThrottle(SimpleRateThrottle):
    scope = 'profile_update'

    def get_cache_key(self, request, view):
        user = request.user
        if user and user.is_authenticated:
            return self.cache_format % {
                'scope': self.scope,
                'ident': user.pk
            }
        return None


class APIKeyRequestThrottle(SimpleRateThrottle):
    scope = 'apikey_request'

    def get_cache_key(self, request, view):
        ip_addr = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip_addr
        }


class DeviceRegistrationThrottle(SimpleRateThrottle):
    scope = 'device_registration'

    def get_cache_key(self, request, view):
        device_id = request.data.get('device_id') if request.method == 'POST' else None
        if not device_id:
            return None
        return self.cache_format % {
            'scope': self.scope,
            'ident': device_id
        }
