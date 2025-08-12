"""
WSGI config for the Django project.
This exposes the WSGI callable as a module-level variable named ``application``.
Used by WSGI servers such as Gunicorn, uWSGI, or mod_wsgi.
Includes diagnostics, environment validation, profiling, and modular logging.
"""

import os
import logging
import platform
import socket
import time
import psutil
from pathlib import Path
from django.core.wsgi import get_wsgi_application
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger("wsgi")


def configure_settings(default_module: str = "config.settings.prod") -> None:
    """
    Configure and validate the Django settings module.
    """
    settings_module = os.environ.get("DJANGO_SETTINGS_MODULE", default_module)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)
    if not settings_module:
        raise ImproperlyConfigured("DJANGO_SETTINGS_MODULE is not set.")
    logger.info(f"WSGI using settings module: {settings_module}")


def log_environment_metadata():
    """
    Log basic environment diagnostics for traceability.
    """
    logger.info("---- Environment Summary ----")
    logger.info(f"Host: {socket.gethostname()}")
    logger.info(f"Platform: {platform.system()} {platform.release()} [{platform.machine()}]")
    logger.info(f"Python: {platform.python_version()}")
    logger.info(f"PID: {os.getpid()}")
    logger.info("-----------------------------")


def log_startup_time(start_time: float):
    """
    Log the duration of the WSGI application startup.
    """
    duration = time.time() - start_time
    logger.info(f"WSGI startup completed in {duration:.2f} seconds")


def verify_critical_envs(required_vars=None):
    """
    Ensure essential environment variables are present.
    """
    if required_vars is None:
        required_vars = ["SECRET_KEY", "DATABASE_URL"]
    for var in required_vars:
        if not os.getenv(var):
            logger.warning(f"Missing critical environment variable: {var}")


def profile_resource_usage():
    """
    Log memory and CPU usage of the current process.
    """
    try:
        process = psutil.Process(os.getpid())
        mem_info = process.memory_info()
        cpu_usage = process.cpu_percent(interval=0.1)
        logger.info(f"Memory Usage: {mem_info.rss / 1024 ** 2:.2f} MB")
        logger.info(f"CPU Usage: {cpu_usage:.2f}%%")
    except Exception as e:
        logger.warning(f"Failed to retrieve resource usage stats: {e}")


def bootstrap_wsgi_application():
    """
    Bootstrap the WSGI application with exception handling.
    """
    try:
        app = get_wsgi_application()
        logger.info("WSGI application initialized successfully.")
        return app
    except Exception as e:
        logger.exception("WSGI application initialization failed: %s", e)
        raise


# Set logging level and format
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Initialization sequence
_start_time = time.time()
configure_settings()
log_environment_metadata()
verify_critical_envs()
application = bootstrap_wsgi_application()
log_startup_time(_start_time)
profile_resource_usage()
