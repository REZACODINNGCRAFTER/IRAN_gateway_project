"""
Development-specific Django settings.
Overrides base.py with development-friendly configurations.
"""

from .base import *
import os
import warnings
import socket

# Development mode
DEBUG = True

# Allow all hosts during development
ALLOWED_HOSTS = ["*"]

# Use console backend for emails
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Enable Django Debug Toolbar if installed
INSTALLED_APPS += [
    "debug_toolbar",
    "django_extensions",  # Optional: shell_plus, graph_models
]

MIDDLEWARE.insert(0, "debug_toolbar.middleware.DebugToolbarMiddleware")

INTERNAL_IPS = [
    "127.0.0.1",
    "localhost",
    socket.gethostbyname(socket.gethostname()),
]

# Example SQLite override
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "dev.sqlite3",
    }
}

# Verbose logging for development
LOGGING["root"]["level"] = "DEBUG"

# Enable Django's built-in runserver_plus if available
try:
    import django_extensions
    RUNSERVER_PLUS = True
except ImportError:
    RUNSERVER_PLUS = False

# Allow weak passwords in development
AUTH_PASSWORD_VALIDATORS = []

# CORS relaxed for development
CORS_ALLOW_ALL_ORIGINS = True

# Development-specific cache (in-memory)
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "dev-cache",
    }
}

# Session cookie settings for local testing
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# Enable Django's deprecation warnings in dev mode
warnings.simplefilter("default", DeprecationWarning)

# Print active environment
print("[INFO] Running in development mode with DEBUG=True")

# Developer-specific local environment overrides (optional)
LOCAL_ENV_FILE = BASE_DIR / ".env.dev"
if LOCAL_ENV_FILE.exists():
    print(f"[INFO] Loading local environment from {LOCAL_ENV_FILE}")
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=LOCAL_ENV_FILE)

# Auto-load developer fixture directory (optional for dev DB seeding)
FIXTURE_DIRS = [BASE_DIR / "fixtures"]

# Allow easier login during development
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login/"

# Use simple password hasher to speed up testing/dev
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Optional: override email host if testing with MailHog or similar
EMAIL_HOST = os.getenv("EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 1025))
