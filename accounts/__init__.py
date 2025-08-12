"""
accounts/__init__.py
Initializes the accounts module for the Django gateway project.
Includes autodiscovery, logger initialization, lifecycle hooks,
metrics logging, environment-aware diagnostics, and dynamic module checks.
"""

import logging
import os
import importlib
from django.utils.module_loading import autodiscover_modules
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.timezone import now
from pathlib import Path

# Define default application config
default_app_config = 'accounts.apps.AccountsConfig'

# Expose components for wildcard imports
__all__ = [
    'signals', 'hooks', 'on_startup', 'on_shutdown', 'check_env',
    'get_build_info', 'log_metrics', 'check_integrity'
]

# Module-level logger setup
logger = logging.getLogger(__name__)
logger.debug("Initializing 'accounts' module.")

# Environment sanity check
def check_env():
    required_vars = ['DJANGO_SETTINGS_MODULE']
    missing = [var for var in required_vars if var not in os.environ]
    if missing:
        logger.error(f"Missing required environment variables: {missing}")
        raise ImproperlyConfigured(f"Missing required environment variables: {', '.join(missing)}")
    logger.debug("Environment check passed.")

# Build metadata retrieval
def get_build_info():
    return {
        "build_time": now().isoformat(),
        "app": "accounts",
        "debug": settings.DEBUG,
        "features": getattr(settings, 'ACCOUNT_FEATURE_FLAGS', {})
    }

# Metrics logger
def log_metrics():
    try:
        metrics_path = Path(settings.BASE_DIR) / 'logs' / 'accounts_metrics.log'
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        with metrics_path.open("a") as f:
            f.write(f"[{now().isoformat()}] Startup metrics: {get_build_info()}\n")
        logger.info("Account metrics logged.")
    except Exception as e:
        logger.warning(f"Could not log metrics: {e}")

# Dynamic integrity check for required modules
def check_integrity():
    modules = ['models', 'views', 'forms']
    for mod in modules:
        try:
            importlib.import_module(f'accounts.{mod}')
            logger.debug(f"Module '{mod}' loaded successfully.")
        except ImportError as e:
            logger.warning(f"Optional module '{mod}' not found or failed to load: {e}")

# Startup hook
def on_startup():
    logger.info("Accounts module startup hook triggered.")
    check_env()
    build_info = get_build_info()
    logger.info(f"Build metadata: {build_info}")
    log_metrics()
    check_integrity()
    # Add startup tasks here (e.g., warmup cache)

# Shutdown hook (manual invocation only)
def on_shutdown():
    logger.info("Accounts module shutdown hook triggered.")
    # Add shutdown tasks here (e.g., close connections)

# Autodiscover any account-level hook modules
try:
    autodiscover_modules('hooks')
    logger.info("Accounts hooks discovered successfully.")
except Exception as e:
    logger.warning(f"Failed to autodiscover hooks in accounts: {e}")

# Attempt to load signals
try:
    from . import signals
    logger.info("Accounts signals loaded.")
except ImportError:
    logger.debug("No signals module found in accounts.")

# Validate optional settings
try:
    if hasattr(settings, 'ACCOUNT_FEATURE_FLAGS'):
        if not isinstance(settings.ACCOUNT_FEATURE_FLAGS, dict):
            raise AssertionError("ACCOUNT_FEATURE_FLAGS must be a dict")
        logger.debug("Account feature flags found and validated.")
except AssertionError as err:
    raise ImproperlyConfigured(f"Invalid setting: {err}")

# Trigger startup tasks
on_startup()
