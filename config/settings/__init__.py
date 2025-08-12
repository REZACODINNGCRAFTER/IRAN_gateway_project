"""
Settings package initializer.
Allows Python to treat the settings directory as a package.
Also enables dynamic configuration loading, validation, environment logging, and diagnostic checks.
"""

import os
import importlib
import logging
import platform
import socket
import sys
from pathlib import Path

logger = logging.getLogger("settings_init")


def configure_logging():
    """
    Configure logging format for consistent diagnostics.
    """
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


def load_settings_module(env_var: str = "DJANGO_SETTINGS_MODULE", default: str = "config.settings.base") -> str:
    """
    Load and validate the Django settings module from environment.
    """
    module_name = os.getenv(env_var, default)
    try:
        importlib.import_module(module_name)
        logger.info(f"Loaded settings module: {module_name}")
    except ImportError as e:
        error_msg = f"Failed to load settings module '{module_name}': {e}"
        logger.exception(error_msg)
        raise ImportError(error_msg)
    return module_name


def validate_critical_settings(required: list = None):
    """
    Ensure that essential environment variables for Django are set.
    """
    if required is None:
        required = ["SECRET_KEY", "DATABASE_URL"]
    for var in required:
        if not os.getenv(var):
            logger.warning(f"Missing critical environment variable: {var}")


def log_environment_summary():
    """
    Log details about the current system environment.
    """
    logger.info("---- Django Settings Environment Summary ----")
    logger.info(f"Host: {socket.gethostname()}")
    logger.info(f"Platform: {platform.system()} {platform.release()} [{platform.machine()}]")
    logger.info(f"Python: {platform.python_version()} @ {sys.executable}")
    logger.info(f"PID: {os.getpid()}")
    logger.info(f"Working Dir: {os.getcwd()}")
    logger.info(f"Active Settings: {os.environ.get('DJANGO_SETTINGS_MODULE', 'Not Set')}")
    logger.info("------------------------------------------------")


def assert_required_files(paths: list = None):
    """
    Assert existence of critical file paths (e.g., .env, static/, media/).
    """
    if paths is None:
        paths = [".env", "static", "media"]
    for path in paths:
        if not Path(path).exists():
            logger.warning(f"Missing expected project file or directory: {path}")


def check_python_version(min_version=(3, 8)):
    """
    Ensure that the Python version meets the minimum requirement.
    """
    if sys.version_info < min_version:
        logger.warning(f"Python {min_version[0]}.{min_version[1]}+ is recommended. Current: {platform.python_version()}")


# Initialization sequence
configure_logging()
selected_settings = load_settings_module()
validate_critical_settings()
log_environment_summary()
assert_required_files()
check_python_version()
