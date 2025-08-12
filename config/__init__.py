"""
Configuration initializer for the Django project.
This module handles environment setup, logging, diagnostics,
and conditional logic for flexible deployment contexts.
"""

import os
import logging
import platform
import socket
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger("config")


def get_env_variable(var_name: str) -> str:
    """
    Return the value of an environment variable or raise an error.
    """
    try:
        return os.environ[var_name]
    except KeyError:
        msg = f"Missing required environment variable: '{var_name}'"
        logger.error(msg)
        raise ImproperlyConfigured(msg)


def load_dotenv(dotenv_path: Path = Path(".env")) -> None:
    """
    Manually load variables from a .env file into the environment.
    """
    if dotenv_path.exists():
        logger.info("Loading environment variables from .env")
        with dotenv_path.open() as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if '=' in line:
                        key, value = line.split("=", 1)
                        os.environ.setdefault(key.strip(), value.strip())
    else:
        logger.warning("No .env file found.")


def set_default_django_settings():
    """
    Ensure DJANGO_SETTINGS_MODULE is set with a fallback default.
    """
    default = "config.settings.dev"
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", default)
    logger.debug(f"DJANGO_SETTINGS_MODULE is '{os.environ['DJANGO_SETTINGS_MODULE']}'")


def setup_logging(level: str = "INFO") -> None:
    """
    Initialize logging for Django configuration context.
    """
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logger.info(f"Logging initialized at {level.upper()} level")


def print_environment_summary():
    """
    Output key system and environment details.
    """
    logger.info("\n---- Django Environment Summary ----")
    logger.info(f"Host: {socket.gethostname()}")
    logger.info(f"Platform: {platform.system()} {platform.release()} [{platform.machine()}]")
    logger.info(f"Python: {platform.python_version()}")
    logger.info(f"Settings: {os.environ.get('DJANGO_SETTINGS_MODULE', 'Not Set')}")
    logger.info("------------------------------------")


def validate_required_envs(required: list[str]) -> None:
    """
    Log a warning for any missing environment variables.
    """
    for var in required:
        if not os.environ.get(var):
            logger.warning(f"Environment variable '{var}' is not set.")


def is_production() -> bool:
    """
    Check if the app is running in production mode.
    """
    return os.environ.get("DJANGO_ENV") == "production"


def detect_docker_environment() -> bool:
    """
    Detect if running inside a Docker container.
    """
    if Path("/.dockerenv").exists():
        logger.info("Docker environment detected.")
        return True
    return False


# ---- Initialization Sequence ----
setup_logging(os.getenv("LOG_LEVEL", "INFO"))
load_dotenv()
set_default_django_settings()
print_environment_summary()
validate_required_envs(["SECRET_KEY", "DATABASE_URL"])
detect_docker_environment()

# Optional import hook
# from .settings.base import BASE_DIR  # noqa
