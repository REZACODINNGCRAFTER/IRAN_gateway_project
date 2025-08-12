"""
Security configuration component for Django project.
This module is meant to be imported into settings/base.py or settings/prod.py.
It enforces secure settings, headers, audit policies, rate-limiting, and account protection.
"""

import os

# Secure cookie settings
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SAMESITE = 'Strict'

# SSL and HTTPS settings
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = int(os.getenv("SECURE_HSTS_SECONDS", 31536000))
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Browser security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Referrer and resource policies
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_EMBEDDER_POLICY = "require-corp"
SECURE_CROSS_ORIGIN_RESOURCE_POLICY = "same-origin"

# Content Security Policy (CSP) example
CSP_DEFAULT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", 'fonts.googleapis.com')
CSP_SCRIPT_SRC = ("'self'", 'cdn.jsdelivr.net')
CSP_IMG_SRC = ("'self'", 'data:')
CSP_FONT_SRC = ("'self'", 'fonts.gstatic.com')

# Password validation policies
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Prevent exposure of detailed error messages in production
DEBUG_PROPAGATE_EXCEPTIONS = False

# Trusted origins for CSRF
CSRF_TRUSTED_ORIGINS = os.getenv("CSRF_TRUSTED_ORIGINS", "https://yourdomain.com").split(",")

# Middleware fallback protection
USE_X_FORWARDED_HOST = True
SECURE_REDIRECT_EXEMPT = [r'^healthcheck/$']

# Security logging
SECURITY_LOGGER_NAME = 'django.security'
SECURITY_LOG_LEVEL = 'WARNING'

# Admin access restrictions
RESTRICT_ADMIN_BY_IP = os.getenv("RESTRICT_ADMIN_BY_IP", "").split(",")

# Session handling
SESSION_SAVE_EVERY_REQUEST = True

# GeoIP restrictions
ENABLE_GEOIP_BLOCKING = os.getenv("ENABLE_GEOIP_BLOCKING", "False") == "True"
ALLOWED_COUNTRIES = os.getenv("ALLOWED_COUNTRIES", "IR,CZ").split(",")

# Rate limiting
ENABLE_RATE_LIMITING = os.getenv("ENABLE_RATE_LIMITING", "True") == "True"
RATE_LIMIT_AUTH_ATTEMPTS = int(os.getenv("RATE_LIMIT_AUTH_ATTEMPTS", 5))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", 300))

# Login auditing
LOGIN_AUDIT_ENABLED = os.getenv("LOGIN_AUDIT_ENABLED", "True") == "True"
LOGIN_AUDIT_LOG_FILE = os.getenv("LOGIN_AUDIT_LOG_FILE", "logs/auth_audit.log")

# Account lockout
ENABLE_ACCOUNT_LOCKOUT = os.getenv("ENABLE_ACCOUNT_LOCKOUT", "True") == "True"
ACCOUNT_LOCKOUT_THRESHOLD = int(os.getenv("ACCOUNT_LOCKOUT_THRESHOLD", 10))
ACCOUNT_LOCKOUT_DURATION = int(os.getenv("ACCOUNT_LOCKOUT_DURATION", 900))  # in seconds

# Suspicious activity alerts
ENABLE_SUSPICIOUS_ACTIVITY_ALERTS = os.getenv("ENABLE_SUSPICIOUS_ACTIVITY_ALERTS", "True") == "True"
SUSPICIOUS_ACTIVITY_ALERT_EMAIL = os.getenv("SUSPICIOUS_ACTIVITY_ALERT_EMAIL", "admin@example.com")

# MFA enforcement (feature toggle)
ENFORCE_TWO_FACTOR_AUTH = os.getenv("ENFORCE_TWO_FACTOR_AUTH", "False") == "True"

# Admin interface lockdown toggle
LOCKDOWN_ADMIN_INTERFACE = os.getenv("LOCKDOWN_ADMIN_INTERFACE", "False") == "True"

# Force HTTPS on cookies for third-party integrations (if any)
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_HTTPONLY = True
