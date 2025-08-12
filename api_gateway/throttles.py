"""
api_gateway/throttles.py

Custom throttle classes for login attempts, anonymous access, OTP requests,
health checks, password resets, file uploads, and other user/API activities.
Includes scoped throttling strategies for high-security workflows.
"""

from rest_framework.throttling import SimpleRateThrottle


class LoginRateThrottle(SimpleRateThrottle):
    scope = 'login'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return f"login-throttle-user-{request.user.id}"
        ident = self.get_ident(request)
        return f"login-throttle-ip-{ident}"


class AnonymousRateThrottle(SimpleRateThrottle):
    scope = 'anon'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return None
        return f"anon-throttle-{self.get_ident(request)}"


class BurstRateThrottle(SimpleRateThrottle):
    scope = 'burst'

    def get_cache_key(self, request, view):
        return f"burst-throttle-{self.get_ident(request)}"


class SustainedRateThrottle(SimpleRateThrottle):
    scope = 'sustained'

    def get_cache_key(self, request, view):
        return f"sustained-throttle-{self.get_ident(request)}"


class OTPRequestRateThrottle(SimpleRateThrottle):
    scope = 'otp_request'

    def get_cache_key(self, request, view):
        ident = self.get_ident(request)
        return f"otp-throttle-{ident}"


class HealthCheckThrottle(SimpleRateThrottle):
    scope = 'health'

    def get_cache_key(self, request, view):
        return f"health-throttle-{self.get_ident(request)}"


class PasswordResetRateThrottle(SimpleRateThrottle):
    scope = 'password_reset'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return f"pwdreset-throttle-user-{request.user.id}"
        return f"pwdreset-throttle-ip-{self.get_ident(request)}"


class APIScopedThrottle(SimpleRateThrottle):
    scope = 'api_scoped'

    def get_cache_key(self, request, view):
        user_scope = request.user.id if request.user.is_authenticated else self.get_ident(request)
        endpoint = view.__class__.__name__.lower()
        return f"api-throttle-{endpoint}-{user_scope}"


class LoginFailureThrottle(SimpleRateThrottle):
    scope = 'login_failure'

    def get_cache_key(self, request, view):
        ident = self.get_ident(request)
        username = request.data.get('username', 'unknown')
        return f"login-failure-{username.lower()}-{ident}"


class UserProfileThrottle(SimpleRateThrottle):
    scope = 'profile'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return f"profile-throttle-{request.user.id}"
        return None


class FileUploadRateThrottle(SimpleRateThrottle):
    scope = 'file_upload'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return f"upload-throttle-{request.user.id}"
        return f"upload-throttle-{self.get_ident(request)}"


class EmailVerificationThrottle(SimpleRateThrottle):
    scope = 'email_verification'

    def get_cache_key(self, request, view):
        email = request.data.get('email', 'unknown')
        return f"email-verification-throttle-{email.lower()}"


class TokenRefreshThrottle(SimpleRateThrottle):
    scope = 'token_refresh'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return f"token-refresh-throttle-{request.user.id}"
        return f"token-refresh-throttle-{self.get_ident(request)}"


class TwoFATokenThrottle(SimpleRateThrottle):
    scope = '2fa_token'

    def get_cache_key(self, request, view):
        username = request.data.get('username', 'unknown')
        return f"2fa-token-throttle-{username.lower()}-{self.get_ident(request)}"


class ContactFormThrottle(SimpleRateThrottle):
    scope = 'contact_form'

    def get_cache_key(self, request, view):
        email = request.data.get('email', 'anonymous')
        return f"contact-throttle-{email.lower()}-{self.get_ident(request)}"


class UserSettingsThrottle(SimpleRateThrottle):
    scope = 'user_settings'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return f"settings-throttle-{request.user.id}"
        return None


class SignupRateThrottle(SimpleRateThrottle):
    scope = 'signup'

    def get_cache_key(self, request, view):
        ident = self.get_ident(request)
        return f"signup-throttle-{ident}"


class MFASetupThrottle(SimpleRateThrottle):
    scope = 'mfa_setup'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return f"mfa-setup-throttle-{request.user.id}"
        return f"mfa-setup-throttle-{self.get_ident(request)}"


class PasswordChangeThrottle(SimpleRateThrottle):
    scope = 'password_change'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return f"password-change-throttle-{request.user.id}"
        return f"password-change-throttle-{self.get_ident(request)}"


class DashboardAPIAccessThrottle(SimpleRateThrottle):
    scope = 'dashboard_api'

    def get_cache_key(self, request, view):
        user_id = request.user.id if request.user.is_authenticated else self.get_ident(request)
        endpoint = view.__class__.__name__.lower()
        return f"dashboard-api-throttle-{endpoint}-{user_id}"
