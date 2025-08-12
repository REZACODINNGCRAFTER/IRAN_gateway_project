"""
Initialization for the gateway app.
Used to define default app configuration and optionally hook signals, middleware, runtime checks, feature flags, and health diagnostics.
"""

import logging
import importlib
import platform
import sys
import os
import psutil
from django.conf import settings
from django.core.checks import register, Tags, Warning, Info, Error
from django.utils.timezone import now

logger = logging.getLogger(__name__)

default_app_config = 'gateway.apps.GatewayConfig'

# Modules to import at startup
startup_modules = [
    "gateway.signals",
    "gateway.permissions",
    "gateway.middleware_hooks",
    "gateway.feature_flags",
    "gateway.lifecycle_hooks",
    "gateway.audit_hooks",
]

for module_path in startup_modules:
    try:
        importlib.import_module(module_path)
        logger.debug(f"Loaded startup module: {module_path}")
    except ImportError:
        logger.info(f"Optional module not found: {module_path}")

# Runtime system check
@register(Tags.security, deploy=True)
def check_gateway_security(app_configs, **kwargs):
    errors = []
    if not getattr(settings, 'SECURE_HSTS_SECONDS', 0):
        errors.append(
            Warning(
                'SECURE_HSTS_SECONDS is not set.',
                hint='Set SECURE_HSTS_SECONDS in production to enable HTTP Strict Transport Security.',
                id='gateway.W001',
            )
        )
    if not getattr(settings, 'SECURE_BROWSER_XSS_FILTER', False):
        errors.append(
            Warning(
                'SECURE_BROWSER_XSS_FILTER is not enabled.',
                hint='Set SECURE_BROWSER_XSS_FILTER = True to protect against reflected XSS attacks.',
                id='gateway.W002',
            )
        )
    if not getattr(settings, 'CSRF_COOKIE_SECURE', False):
        errors.append(
            Warning(
                'CSRF_COOKIE_SECURE is not enabled.',
                hint='Set CSRF_COOKIE_SECURE = True to ensure CSRF cookie is sent over HTTPS only.',
                id='gateway.W003',
            )
        )
    return errors

# Runtime environment compatibility check
@register(Tags.compatibility)
def check_runtime_environment(app_configs, **kwargs):
    messages = []
    python_version = platform.python_version()
    if not python_version.startswith("3.11"):
        messages.append(
            Info(
                f"Python {python_version} detected. Consider upgrading to 3.11 for better performance.",
                id='gateway.I001',
            )
        )
    return messages

# System resource diagnostics
@register(Tags.performance)
def check_resource_limits(app_configs, **kwargs):
    messages = []
    try:
        mem = psutil.virtual_memory()
        if mem.available < 500 * 1024 * 1024:  # less than 500MB
            messages.append(
                Warning(
                    f"Low available memory: {mem.available / (1024 * 1024):.2f} MB",
                    hint='Consider increasing memory for production workloads.',
                    id='gateway.P001',
                )
            )
        cpu_count = psutil.cpu_count(logical=True)
        if cpu_count < 2:
            messages.append(
                Info(
                    f"Low CPU count: {cpu_count} cores",
                    id='gateway.I002',
                )
            )
    except Exception as e:
        messages.append(
            Error(
                f"Failed to check system resources: {e}",
                id='gateway.E001',
            )
        )
    return messages

# Initialization diagnostics
if settings.DEBUG:
    logger.info("[Gateway] App initialized in DEBUG mode")
    logger.debug(f"Startup complete at {now().isoformat()}")
    logger.debug(f"Using settings module: {settings.SETTINGS_MODULE}")
    logger.debug(f"Python executable: {sys.executable}")
    logger.debug(f"Working directory: {os.getcwd()}")
