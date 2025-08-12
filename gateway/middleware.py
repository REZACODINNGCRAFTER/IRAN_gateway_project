"""
Custom middleware for the gateway app.
Includes session expiration handling, role-based access enforcement,
IP address logging, request timing, suspicious activity detection,
request header integrity validation, browser fingerprint verification,
geo-blocking enforcement, device type tagging, login origin auditing,
and user-agent anomaly alerts.
"""

import logging
import time
from datetime import timedelta
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse
from django.core.exceptions import PermissionDenied

logger = logging.getLogger(__name__)

SESSION_TIMEOUT_MINUTES = getattr(settings, "SESSION_TIMEOUT_MINUTES", 15)
SUSPICIOUS_PATHS = getattr(settings, "SUSPICIOUS_PATHS", ["/admin", "/settings"])
FORBIDDEN_COUNTRIES = getattr(settings, "FORBIDDEN_COUNTRIES", [])
ALLOWED_BROWSERS = getattr(settings, "ALLOWED_BROWSERS", ["Chrome", "Firefox", "Safari", "Edge"])


class SessionExpiryMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if not request.user.is_authenticated:
            return
        last_activity = request.session.get("last_activity")
        now = timezone.now().timestamp()
        if last_activity and (now - last_activity > SESSION_TIMEOUT_MINUTES * 60):
            from django.contrib.auth import logout
            logout(request)
            logger.info(f"Session expired for user {request.user.username}")
            return redirect(reverse("login"))
        request.session["last_activity"] = now


class RoleRequiredMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        role_required = getattr(view_func, "required_role", None)
        if role_required and request.user.is_authenticated:
            user_roles = getattr(request.user, "roles", [])
            if role_required not in user_roles:
                logger.warning(f"Unauthorized access attempt by {request.user.username} to {request.path}")
                raise PermissionDenied("You do not have permission to access this resource.")
        return None


class RequestLoggingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        ip = request.META.get("REMOTE_ADDR", "unknown")
        agent = request.META.get("HTTP_USER_AGENT", "unknown")
        logger.info(f"Request from IP {ip} with agent {agent} to {request.path}")


class RequestTimerMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request._start_time = time.time()

    def process_response(self, request, response):
        duration = time.time() - getattr(request, "_start_time", time.time())
        logger.info(f"{request.path} took {duration:.2f} seconds")
        return response


class SuspiciousActivityMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if not request.user.is_authenticated and request.path in SUSPICIOUS_PATHS:
            ip = request.META.get("REMOTE_ADDR", "unknown")
            logger.warning(f"Suspicious unauthenticated access attempt to {request.path} from IP {ip}")


class HeaderIntegrityMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if "HTTP_USER_AGENT" not in request.META or "REMOTE_ADDR" not in request.META:
            logger.warning("Missing critical headers in request.")
            raise PermissionDenied("Invalid request headers.")


class FingerprintVerificationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        expected_fingerprint = request.session.get("fingerprint")
        current_fingerprint = request.META.get("HTTP_USER_AGENT", "") + request.META.get("REMOTE_ADDR", "")
        if expected_fingerprint and expected_fingerprint != current_fingerprint:
            logger.warning(f"Fingerprint mismatch for user {request.user.username if request.user.is_authenticated else 'Anonymous'}")
            raise PermissionDenied("Potential session hijack detected.")


class GeoBlockMiddleware(MiddlewareMixin):
    def process_request(self, request):
        country_code = request.META.get("HTTP_CF_IPCOUNTRY", "")
        if country_code.upper() in FORBIDDEN_COUNTRIES:
            logger.warning(f"Blocked access from forbidden country: {country_code}")
            raise PermissionDenied("Access from your region is restricted.")


class DeviceTypeTagMiddleware(MiddlewareMixin):
    def process_request(self, request):
        agent = request.META.get("HTTP_USER_AGENT", "")
        if "Mobile" in agent:
            request.device_type = "Mobile"
        elif "Tablet" in agent:
            request.device_type = "Tablet"
        else:
            request.device_type = "Desktop"
        logger.info(f"Device type tagged: {request.device_type}")


class UserAgentAnomalyMiddleware(MiddlewareMixin):
    def process_request(self, request):
        user_agent = request.META.get("HTTP_USER_AGENT", "Unknown")
        if not any(browser in user_agent for browser in ALLOWED_BROWSERS):
            logger.warning(f"Unrecognized browser detected: {user_agent}")


class LoginOriginAuditMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.user.is_authenticated and request.path == reverse("dashboard"):
            ip = request.META.get("REMOTE_ADDR", "unknown")
            agent = request.META.get("HTTP_USER_AGENT", "unknown")
            logger.info(f"User {request.user.username} accessed dashboard from IP {ip} with agent {agent}")
