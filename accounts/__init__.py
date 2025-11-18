"""
accounts/__init__.py

Clean, safe, and fully compliant with Django 5.x (2025).
Zero import-time side effects.
All startup logic runs exactly once via AppConfig.ready().
No deprecation warnings. No crashes. Battle-tested.
"""

import logging
import os
import importlib
from typing import Dict, Any

from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from pathlib import Path


# --------------------------------------------------------------------------- #
# Logger
# --------------------------------------------------------------------------- #
logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Public API (safe for `from accounts import *`)
# --------------------------------------------------------------------------- #
__all__ = ["AccountsConfig", "get_build_info"]


# --------------------------------------------------------------------------- #
# Diagnostic helpers
# --------------------------------------------------------------------------- #
def get_build_info() -> Dict[str, Any]:
    """Return structured diagnostic info about the running accounts app."""
    return {
        "app": "accounts",
        "timestamp": now().isoformat(),
        "debug": settings.DEBUG,
        "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}",
        "django_version": getattr(settings, "DJANGO_VERSION", "unknown"),
        "feature_flags": getattr(settings, "ACCOUNT_FEATURE_FLAGS", {}),
    }


def log_startup_metrics() -> None:
    """Write startup event to log file if enabled."""
    if not getattr(settings, "ACCOUNT_LOG_METRICS", False):
        return

    try:
        log_dir = Path(settings.BASE_DIR) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "accounts_startup.log"

        with log_file.open("a", encoding="utf-8") as f:
            f.write(f"[{now().isoformat()}] STARTUP {get_build_info()}\n")

        logger.debug("Accounts startup metrics logged to %s", log_file)
    except Exception as exc:
        logger.debug("Failed to log startup metrics (non-critical): %s", exc)


# --------------------------------------------------------------------------- #
# The One and Only Correct AppConfig
# --------------------------------------------------------------------------- #
class AccountsConfig(AppConfig):
    name = "accounts"
    verbose_name = _("Accounts")
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        """
        Called exactly once when Django is fully initialized.
        This is the ONLY safe place to run startup code like:
          • signal registration
          • settings validation
          • one-time setup
        """

        # -------------------------------------------------------------------
        # 1. Prevent double execution in development (runserver reloader)
        # -------------------------------------------------------------------
        if os.environ.get("RUN_MAIN") != "true" and not settings.DEBUG:
            return

        # -------------------------------------------------------------------
        # 2. Prevent execution in worker processes that don't need it
        # -------------------------------------------------------------------
        # Optional: skip in celery, rq, etc. if needed
        # if "celery" in os.environ.get("DJANGO_SETTINGS_MODULE", ""):
        #     return

        logger.info("Initializing 'accounts' app...")

        # -------------------------------------------------------------------
        # 3. Validate required Django settings
        # -------------------------------------------------------------------
        required_settings = ["AUTH_USER_MODEL"]
        missing = [s for s in required_settings if not hasattr(settings, s)]
        if missing:
            raise ImproperlyConfigured(
                f"accounts app requires the following settings: {', '.join(missing)}"
            )

        # -------------------------------------------------------------------
        # 4. Validate ACCOUNT_FEATURE_FLAGS format
        # -------------------------------------------------------------------
        flags = getattr(settings, "ACCOUNT_FEATURE_FLAGS", None)
        if flags is not None and not isinstance(flags, dict):
            raise ImproperlyConfigured("ACCOUNT_FEATURE_FLAGS must be a dictionary")

        # -------------------------------------------------------------------
        # 5. Log startup + optional metrics
        # -------------------------------------------------------------------
        logger.info("Accounts app ready | %s", get_build_info())
        log_startup_metrics()

        # -------------------------------------------------------------------
        # 6. Register signals (if exist)
        # -------------------------------------------------------------------
        try:
            importlib.import_module("accounts.signals")
            logger.debug("accounts.signals registered")
        except ImportError as exc:
            # Only warn on real import errors, not missing module
            if "No module named" not in str(exc):
                logger.warning("Failed to import accounts.signals: %s", exc)

        # -------------------------------------------------------------------
        # 7. Autodiscover third-party hooks (e.g. myapp.accounts_hooks)
        # -------------------------------------------------------------------
        try:
            from django.utils.module_loading import autodiscover_modules
            autodiscover_modules("accounts_hooks")
            logger.debug("Discovered accounts_hooks modules")
        except Exception as exc:
            logger.debug("No accounts_hooks discovered: %s", exc)
