"""
Production-specific Django settings.
Overrides base.py with secure production-ready configurations.
"""

from .base import *
import os
import logging.config

# Production mode
DEBUG = False

# Must be explicitly set via environment
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "").split(",")

# Secure settings
SECURE_HSTS_SECONDS = int(os.getenv("SECURE_HSTS_SECONDS", 31536000))
SECURE_HSTS_INCLUDE_SUBDOMAINS = os.getenv("SECURE_HSTS_INCLUDE_SUBDOMAINS", "True") == "True"
SECURE_HSTS_PRELOAD = os.getenv("SECURE_HSTS_PRELOAD", "True") == "True"
SECURE_SSL_REDIRECT = os.getenv("SECURE_SSL_REDIRECT", "True") == "True"
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "True") == "True"
CSRF_COOKIE_SECURE = os.getenv("CSRF_COOKIE_SECURE", "True") == "True"
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Email backend (use SMTP in production)
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.example.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "webmaster@example.com")

# Use PostgreSQL in production
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "gateway"),
        "USER": os.getenv("POSTGRES_USER", "gateway"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", "password"),
        "HOST": os.getenv("POSTGRES_HOST", "localhost"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
    }
}

# Logging configuration
LOGGING["root"]["level"] = "WARNING"
LOGGING["handlers"]["file"] = {
    "level": "WARNING",
    "class": "logging.FileHandler",
    "filename": BASE_DIR / "logs" / "django.log",
    "formatter": "verbose",
}
LOGGING["formatters"] = {
    "verbose": {
        "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    }
}
LOGGING["root"]["handlers"].append("file")

# Cache (e.g., Redis)
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": os.getenv("REDIS_URL", "redis://127.0.0.1:6379/1"),
    }
}

# CORS (should be restricted in production)
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")

# Static and media file configuration (for WSGI/Nginx handling)
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_ROOT = BASE_DIR / "mediafiles"

# Enforce strong password validation in production
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Security audit: print environment status
if not ALLOWED_HOSTS or ALLOWED_HOSTS == [""]:
    raise ValueError("[ERROR] ALLOWED_HOSTS must be explicitly set in production.")

print("[INFO] Production settings loaded. DEBUG=False")

# Sentry error tracking
SENTRY_DSN = os.getenv("SENTRY_DSN")
if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[DjangoIntegration()],
        traces_sample_rate=0.1,
        send_default_pii=True,
    )

# Content Security Policy (if django-csp is installed)
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "https://trustedscripts.example.com")
CSP_STYLE_SRC = ("'self'", "https://trustedstyles.example.com")

# Redis connection pool size
REDIS_CONNECTION_POOL_MAX_CONNECTIONS = int(os.getenv("REDIS_CONNECTION_POOL_MAX_CONNECTIONS", 20))

# Internal IPs for conditional features
INTERNAL_IPS = os.getenv("INTERNAL_IPS", "127.0.0.1,localhost").split(",")

# Session and security expiration settings
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_AGE = 3600  # 1 hour

# Additional security headers
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_EMBEDDER_POLICY = "require-corp"
SECURE_CROSS_ORIGIN_RESOURCE_POLICY = "same-origin"
