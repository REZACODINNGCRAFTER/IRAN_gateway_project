"""
Custom permission classes for the Gateway application using Django REST Framework.
Includes role-based access, IP validation, OTP checks, user-agent enforcement,
object-level access control, MFA validation, device fingerprinting, referer headers,
geo/IP/method/time-based restrictions, secure header enforcement, and advanced session rules.
"""

from rest_framework import permissions
from datetime import datetime, time as dtime, timedelta


class IsAdminOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS or \
               (request.user and request.user.is_authenticated and request.user.is_staff)


class HasRolePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        allowed_roles = getattr(view, 'allowed_roles', [])
        user_roles = getattr(request.user, 'roles', [])
        return request.user.is_authenticated and any(role in allowed_roles for role in user_roles)


class IsVerifiedAndFromWhitelistedIP(permissions.BasePermission):
    def has_permission(self, request, view):
        allowed_ips = getattr(view, 'allowed_ips', [])
        ip = request.META.get('REMOTE_ADDR')
        profile = getattr(request.user, 'profile', None)
        return request.user.is_authenticated and profile and profile.is_verified and ip in allowed_ips


class HasOTPVerified(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.session.get("2fa_passed", False)


class IsSuperUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser


class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return request.method in permissions.SAFE_METHODS or obj.owner == request.user


class IsFromAllowedUserAgent(permissions.BasePermission):
    def has_permission(self, request, view):
        agents = getattr(view, 'allowed_user_agents', [])
        return any(agent in request.META.get("HTTP_USER_AGENT", "") for agent in agents)


class IsAuthenticatedDuringWorkingHours(permissions.BasePermission):
    def has_permission(self, request, view):
        now = datetime.now().time()
        return request.user.is_authenticated and dtime(8) <= now <= dtime(18)


class IsAuthenticatedAndEmailConfirmed(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and getattr(request.user, 'email_verified', False)


class HasMFACompleted(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.session.get("mfa_completed", False)


class IsFromTrustedDevice(permissions.BasePermission):
    def has_permission(self, request, view):
        devices = request.session.get("trusted_devices", [])
        return request.META.get("HTTP_X_DEVICE_FINGERPRINT") in devices


class RefererHeaderAllowed(permissions.BasePermission):
    def has_permission(self, request, view):
        allowed = getattr(view, 'allowed_referers', [])
        return any(ref in request.META.get("HTTP_REFERER", "") for ref in allowed)


class IsFromAllowedCountry(permissions.BasePermission):
    def has_permission(self, request, view):
        return getattr(request, 'country_code', None) in getattr(view, 'allowed_countries', [])


class IsMethodAllowed(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.method in getattr(view, 'allowed_methods', permissions.SAFE_METHODS)


class IsRequestSecure(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.is_secure()


class IsRequestFromInternalNetwork(permissions.BasePermission):
    def has_permission(self, request, view):
        ip = request.META.get('REMOTE_ADDR', '')
        return ip.startswith(('192.168.', '10.', '172.'))


class HasHeaderTokenMatch(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.session.get('header_token') == request.headers.get('X-Custom-Token')


class IsReadOnlyMethod(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS


class IsAuthenticatedAndActive(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_active


class HasVerifiedPhoneNumber(permissions.BasePermission):
    def has_permission(self, request, view):
        profile = getattr(request.user, 'profile', None)
        return request.user.is_authenticated and profile and profile.phone_verified


class IsWithinLoginQuota(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.session.get('login_attempts', 0) <= getattr(view, 'max_login_attempts', 5)


class IsSessionFresh(permissions.BasePermission):
    def has_permission(self, request, view):
        start = request.session.get('session_start')
        return bool(start and datetime.now() - datetime.fromisoformat(start) < timedelta(hours=1))


class IsUsingSecureHeaders(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.headers.get('X-Content-Type-Options') == 'nosniff' and \
               request.headers.get('X-Frame-Options') == 'DENY'


class HasRecentPasswordChange(permissions.BasePermission):
    def has_permission(self, request, view):
        last_changed = getattr(request.user, 'password_last_changed', None)
        return request.user.is_authenticated and last_changed and \
               (datetime.now() - last_changed).days < 90


class IsApiKeyValid(permissions.BasePermission):
    def has_permission(self, request, view):
        api_keys = getattr(view, 'valid_api_keys', [])
        return request.headers.get("X-API-Key") in api_keys


class HasVerifiedEmailDomain(permissions.BasePermission):
    def has_permission(self, request, view):
        domain = getattr(request.user, 'email', '').split('@')[-1]
        return domain in getattr(view, 'allowed_email_domains', [])


class IsNotBlacklistedUser(permissions.BasePermission):
    def has_permission(self, request, view):
        blacklisted_users = getattr(view, 'blacklisted_users', [])
        return request.user.username not in blacklisted_users


class HasUserProfileComplete(permissions.BasePermission):
    def has_permission(self, request, view):
        profile = getattr(request.user, 'profile', None)
        return request.user.is_authenticated and profile and profile.is_complete


class IsRecentLogin(permissions.BasePermission):
    def has_permission(self, request, view):
        login_time = request.session.get('last_login_time')
        return login_time and (datetime.now() - datetime.fromisoformat(login_time)) < timedelta(minutes=15)


class HasSessionToken(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.session.get('session_token'))


class HasConsentedToLatestPolicy(permissions.BasePermission):
    def has_permission(self, request, view):
        consent_date = getattr(request.user, 'policy_consent_date', None)
        policy_updated_at = getattr(view, 'policy_updated_at', datetime.min)
        return consent_date and consent_date >= policy_updated_at


class HasValidReferrerToken(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.COOKIES.get('referrer_token') in getattr(view, 'valid_referrer_tokens', [])


class IsRequestRateCompliant(permissions.BasePermission):
    def has_permission(self, request, view):
        rate = request.session.get('recent_request_count', 0)
        max_rate = getattr(view, 'max_request_rate', 50)
        return rate <= max_rate


class IsUsingWhitelistedBrowser(permissions.BasePermission):
    def has_permission(self, request, view):
        allowed_browsers = getattr(view, 'allowed_browsers', [])
        ua = request.META.get('HTTP_USER_AGENT', '')
        return any(browser in ua for browser in allowed_browsers)


class IsTimezoneAllowed(permissions.BasePermission):
    def has_permission(self, request, view):
        tz = getattr(request.user, 'timezone', None)
        return tz in getattr(view, 'allowed_timezones', [])
