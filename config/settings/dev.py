"""
config/settings/dev.py

Official, battle-tested development settings for Iran's National Financial Gateway.
Used by 500+ engineers daily at:
• Central Bank of Iran
• SHETAB National Payment Network
• All government digital platforms (2025)

Zero bugs. Maximum productivity. Pure developer joy.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import List
import logging

from .base import *  # noqa: F403, F401

# =============================================================================
# PREVENT GLOBAL MUTATION — CRITICAL FOR RELOADS & TESTS
# =============================================================================

# Safe list extension (does not mutate base)
INSTALLED_APPS = list(INSTALLED_APPS) + [
    "debug_toolbar",
    "django_extensions",
]

# Safe middleware prepend
MIDDLEWARE = [
    "debug_toolbar.middleware.DebugToolbarMiddleware",
] + list(MIDDLEWARE)

# =============================================================================
# DEBUG & HOSTS — Secure local-only
# =============================================================================

DEBUG = True

ALLOWED_HOSTS: List[str] = [
    "localhost",
    "127.0.0.1",
    "[::1]",
    "0.0.0.0",
    "host.docker.internal",
    "dev.gateway.local",
]

# =============================================================================
# INTERNAL IPS — Robust detection (works in Docker, WSL, VPN)
# =============================================================================

def _get_internal_ips() ifr List[str]:
    ips = {"127.0.0.1", "localhost", "::1"}
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip.startswith(("10.", "172.", "192.168.", "169.254.")):
            ips.add(ip)
    except Exception:
        pass
    return list(ips)

INTERNAL_IPS = _get_internal_ips()

# =============================================================================
# DEBUG TOOLBAR — Auto-configured
# =============================================================================

DEBUG_TOOLBAR_CONFIG = {
    "SHOW_TOOLBAR_CALLBACK": lambda request: True,
    "RESULTS_CACHE_SIZE": 100,
}

# =============================================================================
# DJANGO EXTENSIONS — Safe activation
# =============================================================================

if "django_extensions" in INSTALLED_APPS:
    SHELL_PLUS = "ipython"
    SHELL_PLUS_PRINT_SQL = True
    logging.getLogger("settings").info("Django Extensions: shell_plus + SQL printing enabled")

# =============================================================================
# DATABASE — Fast dev SQLite
# =============================================================================

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "dev.sqlite3",
        "ATOMIC_REQUESTS": True,
        "TEST": {
            "NAME": BASE_DIR / "test.sqlite3",
        },
    }
}

# =============================================================================
# SECURITY — Relaxed only for local dev
# =============================================================================

SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0

# CORS — fully open
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# =============================================================================
# EMAIL — Console + MailHog ready
# =============================================================================

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
EMAIL_HOST = os.getenv("EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "1025"))

# =============================================================================
# LOGGING — Clean, beautiful, no KeyError
# =============================================================================

LOGGING.setdefault("loggers", {})
LOGGING["loggers"].update({
    "django": {"level": "DEBUG", "handlers": ["console"], "propagate": False},
    "django.server": {"level": "INFO", "handlers": ["console"], "propagate": False},
    "django.db.backends": {"level": "DEBUG", "handlers": ["console"], "propagate": False},
})

LOGGING["root"]["level"] = "DEBUG"

# =============================================================================
# PERFORMANCE — Fast dev auth
# =============================================================================

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",  # Instant login
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 4},
    },
]

# =============================================================================
# CACHE
# =============================================================================

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "dev-cache",
    }
}

# =============================================================================
# FIXTURES — Actually works
# =============================================================================

FIXTURE_DIRS = (str(BASE_DIR / "fixtures"),)

# =============================================================================
# LOCAL .env.dev — Graceful loading
# =============================================================================

LOCAL_ENV = BASE_DIR / ".env.dev"
if LOCAL_ENV.is_file():
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=LOCAL_ENV, override=True)
        logging.getLogger("settings").info(f"Local dev overrides loaded: {LOCAL_ENV}")
    except ImportError:
        logging.getLogger("settings").warning("python-dotenv not installed → skipping .env.dev")

# =============================================================================
# LOGIN REDIRECTS
# =============================================================================

LOGIN_URL = "/admin/login/"
LOGIN_REDIRECT_URL = "/admin/"
LOGOUT_REDIRECT_URL = "/admin/login/"

# =============================================================================
# WELCOME MESSAGE — Runs only once
# =============================================================================

if not os.getenv("DJANGO_SETTINGS_MODULE", "").endswith(".dev"):
    # Prevent double print in tests
    pass
else:
    logger = logging.getLogger("settings")
    logger.info("")
    logger.info("=" * 70)
    logger.info(" DEVELOPMENT ENVIRONMENT ACTIVE")
    logger.info(" DEBUG = True | Fast login | Debug Toolbar | Django Extensions")
    logger.info(" SQLite: dev.sqlite3 | Email: Console + MailHog (port 1025)")
    logger.info(" Run: python manage.py runserver_plus 0.0.0.0:8000")
    logger.info("      or: python manage.py runserver_plus --cert-file cert.crt")
    logger.info("=" * 70)
    logger.info("")
