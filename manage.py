#!/usr/bin/env python
"""
Django's command-line utility for administrative tasks.
"""
import os
import sys
import logging
from pathlib import Path
from importlib.util import find_spec


def main():
    """
    Entry point for Django management commands.
    """
    configure_logging()

    # Automatically select settings module if not already defined
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

    # Optional: Run preflight checks
    run_preflight_checks()

    # Optional: Show helpful debug info
    show_debug_info()

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        logging.critical(
            "Couldn't import Django. Make sure it's installed and available in your PYTHONPATH.\n"
            "Did you forget to activate a virtual environment?"
        )
        raise ImportError(
            "Couldn't import Django. Make sure it's installed and available in your PYTHONPATH.\n"
            "Did you forget to activate a virtual environment?"
        ) from exc

    execute_from_command_line(sys.argv)


def run_preflight_checks():
    """
    Perform preflight checks before executing commands.
    """
    check_required_files()
    check_python_version()
    check_environment_variables()
    check_django_installed()


def check_required_files():
    """
    Check for required configuration files.
    """
    required_files = ['.env']
    missing = [f for f in required_files if not Path(f).is_file()]
    if missing:
        logging.warning(f"Missing required file(s): {', '.join(missing)}")


def check_python_version():
    """
    Warn if running with unsupported Python version.
    """
    if sys.version_info < (3, 8):
        logging.warning("Python 3.8 or higher is recommended.")


def check_environment_variables():
    """
    Ensure critical environment variables are set.
    """
    critical_vars = ['DJANGO_SECRET_KEY']
    for var in critical_vars:
        if not os.getenv(var):
            logging.warning(f"Environment variable '{var}' is not set.")


def check_django_installed():
    """
    Check if Django is installed in the environment.
    """
    if not find_spec("django"):
        logging.error("Django is not installed. Run 'pip install django'.")


def show_debug_info():
    """
    Print useful debug info for developers.
    """
    logging.info(f"Using settings: {os.environ.get('DJANGO_SETTINGS_MODULE')}")
    logging.info(f"Python executable: {sys.executable}")
    logging.info(f"Python version: {'.'.join(map(str, sys.version_info[:3]))}")


def configure_logging():
    """
    Set up basic logging to console.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s] %(message)s'
    )


if __name__ == '__main__':
    main()
