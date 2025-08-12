"""
Custom decorators for gateway access control and auditing.
Includes role enforcement, audit logging, 2FA checks,
IP restriction, method restriction, time-based access control,
user agent restrictions, login history tracking, and referer validation.
"""

import logging
from functools import wraps
from datetime import time as dtime, datetime
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseNotAllowed
from django.shortcuts import redirect
from django.urls import reverse

logger = logging.getLogger(__name__)


def role_required(role):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            user_roles = getattr(request.user, "roles", [])
            if not request.user.is_authenticated or role not in user_roles:
                logger.warning(f"Access denied for {request.user.username if request.user.is_authenticated else 'Anonymous'} - Missing role: {role}")
                raise PermissionDenied("You do not have the required role.")
            return view_func(request, *args, **kwargs)
        _wrapped_view.required_role = role
        return _wrapped_view
    return decorator


def audit_log(action_name):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            user = request.user.username if request.user.is_authenticated else "Anonymous"
            logger.info(f"{action_name} accessed by {user} at {request.path}")
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def require_2fa(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.session.get("2fa_passed", False):
            logger.warning(f"2FA not completed for {request.user.username if request.user.is_authenticated else 'Anonymous'}")
            return redirect(reverse("gateway:otp_verify"))
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def ip_restricted(allowed_ips):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            ip = request.META.get("REMOTE_ADDR")
            if ip not in allowed_ips:
                logger.warning(f"Blocked IP {ip} from accessing {request.path}")
                raise PermissionDenied("Access denied from this IP address.")
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def method_allowed(methods):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if request.method not in methods:
                logger.warning(f"Method {request.method} not allowed on {request.path}")
                return HttpResponseNotAllowed(methods)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def access_during_hours(start_time: dtime, end_time: dtime):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            now = datetime.now().time()
            if not (start_time <= now <= end_time):
                logger.warning(f"Access attempt to {request.path} outside permitted hours by {request.user.username if request.user.is_authenticated else 'Anonymous'}")
                raise PermissionDenied("This resource is not available at this time.")
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def user_agent_allowed(allowed_agents):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            user_agent = request.META.get("HTTP_USER_AGENT", "")
            if not any(agent in user_agent for agent in allowed_agents):
                logger.warning(f"Blocked unapproved User-Agent: {user_agent}")
                raise PermissionDenied("Unsupported browser or device.")
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def track_login_history(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated:
            ip = request.META.get("REMOTE_ADDR", "unknown")
            agent = request.META.get("HTTP_USER_AGENT", "unknown")
            logger.info(f"Login history - User: {request.user.username}, IP: {ip}, Agent: {agent}")
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def referer_required(allowed_referers):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            referer = request.META.get("HTTP_REFERER", "")
            if not any(allowed in referer for allowed in allowed_referers):
                logger.warning(f"Invalid referer {referer} for {request.path}")
                raise PermissionDenied("Invalid request origin.")
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
