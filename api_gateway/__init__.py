"""
api_gateway/__init__.py

This file initializes the API Gateway package and sets up 
package-level behaviors, diagnostics, runtime metrics, and security checks.
"""

import logging
import os
from datetime import datetime
import importlib
import socket
import platform
import sys
import time
import tracemalloc
import threading
import uuid

logger = logging.getLogger(__name__)
logger.info("API Gateway package initialized.")

SESSION_ID = str(uuid.uuid4())
START_TIME = time.time()

def ready():
    """
    Called when the API gateway package is ready.
    Initializes diagnostic checks and metrics.
    """
    logger.debug("API Gateway is ready for use.")
    check_environment()
    log_startup_info()
    register_dynamic_modules()
    register_health_checks()
    check_system_requirements()
    log_host_info()
    initialize_profiling()
    record_startup_metrics()
    start_background_uptime_logger()
    enforce_runtime_guards()

def check_environment():
    required_vars = ['API_SECRET_KEY', 'JWT_EXPIRATION_DELTA']
    for var in required_vars:
        if not os.getenv(var):
            logger.warning(f"Missing required environment variable: {var}")

def log_startup_info():
    logger.info("Startup timestamp: %s", datetime.utcnow().isoformat())
    logger.info("Debug mode: %s", os.getenv('DEBUG', 'not specified'))
    logger.info("Session ID: %s", SESSION_ID)

def register_dynamic_modules():
    optional_modules = ['api_gateway.metrics', 'api_gateway.profiling']
    for module in optional_modules:
        try:
            importlib.import_module(module)
            logger.info("Successfully loaded optional module: %s", module)
        except ImportError:
            logger.info("Optional module not found: %s", module)

def register_health_checks():
    logger.info("Health checks registered (placeholder)")

def check_system_requirements():
    if sys.version_info < (3, 8):
        logger.warning("Python 3.8+ recommended. Detected: %s", sys.version)

def log_host_info():
    logger.info("Host: %s", socket.gethostname())
    logger.info("Platform: %s", platform.platform())
    logger.info("Python version: %s", sys.version)

def initialize_profiling():
    if os.getenv("ENABLE_PROFILING") == "1":
        tracemalloc.start()
        logger.info("Memory profiling enabled via tracemalloc.")

def record_startup_metrics():
    uptime = time.time() - START_TIME
    logger.info("Initial startup time: %.2f seconds", uptime)

    if tracemalloc.is_tracing():
        current, peak = tracemalloc.get_traced_memory()
        logger.info("Memory usage: Current = %.2f KB, Peak = %.2f KB", current / 1024, peak / 1024)

def start_background_uptime_logger():
    def log_uptime():
        while True:
            time.sleep(60)
            elapsed = time.time() - START_TIME
            logger.info("Uptime: %.2f seconds (session: %s)", elapsed, SESSION_ID)

    thread = threading.Thread(target=log_uptime, daemon=True)
    thread.start()

def enforce_runtime_guards():
    """
    Apply runtime protections such as disabling debug mode in production.
    """
    if os.getenv("ENV") == "production" and os.getenv("DEBUG") == "True":
        logger.critical("DEBUG mode should not be enabled in production!")

    max_threads = os.getenv("MAX_THREAD_LIMIT")
    if max_threads and threading.active_count() > int(max_threads):
        logger.warning("Thread count exceeds configured maximum (%s).", max_threads)
