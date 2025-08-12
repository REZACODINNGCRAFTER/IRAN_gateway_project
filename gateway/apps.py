"""
App configuration for the gateway application.
Handles ready-time signal and system hook registrations, diagnostics, startup checks, and environment fingerprinting.
Includes additional readiness checks, database ping, conditional email alerts, and optional integration tests.
"""

from django.apps import AppConfig
import logging
import socket
import os
import sys
import platform
from datetime import datetime
from django.db import connections, OperationalError
from django.core.mail import send_mail
from django.core.checks import run_checks

logger = logging.getLogger(__name__)

class GatewayConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'gateway'
    verbose_name = "Access Gateway"

    def ready(self):
        self._register_hooks()
        self._log_environment_info()
        self._check_essential_settings()
        self._log_platform_info()
        self._record_startup_timestamp()
        self._verify_database_connection()
        self._send_startup_notification_if_enabled()
        self._run_system_checks()
        self._log_memory_usage()

    def _register_hooks(self):
        try:
            import gateway.signals
            import gateway.middleware_hooks
            import gateway.lifecycle_hooks
            import gateway.audit_hooks
            logger.info("[Gateway] Hooks and signals initialized.")
        except ImportError as e:
            logger.warning(f"[Gateway] Optional hook import failed: {e}")

    def _log_environment_info(self):
        hostname = socket.gethostname()
        environment = os.environ.get("DJANGO_ENV", "unknown")
        logger.info(f"[Gateway] Hostname: {hostname}")
        logger.info(f"[Gateway] Environment: {environment}")
        logger.debug(f"[Gateway] Process ID: {os.getpid()}")

    def _check_essential_settings(self):
        from django.conf import settings
        if not getattr(settings, "SECRET_KEY", None):
            logger.warning("[Gateway] SECRET_KEY is not defined in settings.")
        if not getattr(settings, "ALLOWED_HOSTS", []):
            logger.warning("[Gateway] ALLOWED_HOSTS is empty.")
        if not getattr(settings, "SECURE_HSTS_SECONDS", None):
            logger.warning("[Gateway] SECURE_HSTS_SECONDS is not defined (recommended for production).")

    def _log_platform_info(self):
        logger.debug(f"[Gateway] Python version: {platform.python_version()}")
        logger.debug(f"[Gateway] Platform: {platform.system()} {platform.release()}")
        logger.debug(f"[Gateway] Executable: {sys.executable}")

    def _record_startup_timestamp(self):
        timestamp = datetime.utcnow().isoformat()
        logger.info(f"[Gateway] App startup timestamp (UTC): {timestamp}")

    def _verify_database_connection(self):
        try:
            db_conn = connections['default']
            db_conn.cursor()
            logger.info("[Gateway] Database connection verified.")
        except OperationalError as e:
            logger.error(f"[Gateway] Database connection failed: {e}")

    def _send_startup_notification_if_enabled(self):
        from django.conf import settings
        if getattr(settings, "GATEWAY_STARTUP_EMAIL_ENABLED", False):
            try:
                send_mail(
                    subject="[Gateway] Startup Notification",
                    message="Gateway app has started successfully.",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[admin[1] for admin in settings.ADMINS],
                    fail_silently=True,
                )
                logger.info("[Gateway] Startup notification email sent.")
            except Exception as e:
                logger.warning(f"[Gateway] Failed to send startup email: {e}")

    def _run_system_checks(self):
        errors = run_checks()
        if errors:
            logger.warning(f"[Gateway] System checks reported {len(errors)} issue(s).")
        else:
            logger.info("[Gateway] All system checks passed.")

    def _log_memory_usage(self):
        try:
            import psutil
            process = psutil.Process(os.getpid())
            mem = process.memory_info().rss / 1024 / 1024
            logger.debug(f"[Gateway] Memory usage: {mem:.2f} MB")
        except ImportError:
            logger.debug("[Gateway] psutil not installed, skipping memory usage logging.")
