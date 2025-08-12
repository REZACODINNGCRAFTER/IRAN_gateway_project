"""
Package initializer for gateway.tests

This module ensures test discovery, configures logging and warning suppression,
and prepares the Django environment for isolated or CI/CD testing.
Also includes utilities for test diagnostics and resource validation.
"""

import logging
import warnings
import os
import sys
import django
import time
from django.conf import settings

from .test_views import *
from .test_api import *
from .test_security import *

# Suppress unnecessary warnings in the test environment
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=ResourceWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Configure a test-specific logger
logger = logging.getLogger("gateway.tests")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

logger.debug("Initializing gateway.tests package...")

# Auto-configure Django for standalone test execution
if not settings.configured:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
    django.setup()
    logger.debug("Django settings configured for testing.")

def report_test_env():
    """Logs key testing environment information."""
    logger.info(f"Python Version: {sys.version.splitlines()[0]}")
    logger.info(f"Django Version: {django.get_version()}")
    logger.info("Relevant Environment Variables:")
    for key in sorted(k for k in os.environ if k.startswith("DJANGO")):
        logger.info(f"  {key} = {os.environ[key]}")

def is_ci_environment():
    """Returns True if running in a CI environment."""
    return os.getenv("CI", "false").lower() == "true"

def enforce_test_constraints():
    """Example runtime constraints for tests, e.g., SQLite enforcement in CI."""
    if is_ci_environment() and 'sqlite3' not in settings.DATABASES['default']['ENGINE']:
        raise RuntimeError("CI environment must use SQLite database backend")

def measure_test_startup_time(start_time):
    """Reports test package load time."""
    duration = time.time() - start_time
    logger.info(f"Test environment initialized in {duration:.2f} seconds")

def validate_test_directories():
    """Ensure expected directories like test_logs and test_tmp exist."""
    required_dirs = ["test_logs", "test_tmp"]
    for d in required_dirs:
        if not os.path.exists(d):
            os.makedirs(d)
            logger.debug(f"Created missing test directory: {d}")

# Execution
_start_time = time.time()
report_test_env()
enforce_test_constraints()
validate_test_directories()
measure_test_startup_time(_start_time)

logger.debug("gateway.tests package ready.")
