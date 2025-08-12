"""
Logging configuration component for Django project.
This module is meant to be imported into settings/base.py
Includes advanced features like log rotation, email alerts, external log forwarding,
performance monitoring, and remote syslog integration.
"""

import os
from pathlib import Path
from logging.handlers import RotatingFileHandler, SMTPHandler, SysLogHandler

BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

SYSLOG_ADDRESS = os.getenv("SYSLOG_ADDRESS", None)
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", 514))

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "simple": {
            "format": "%(levelname)s %(message)s"
        },
        "performance": {
            "format": "%(asctime)s - %(message)s"
        },
        "json": {
            "format": '{"time": "%(asctime)s", "level": "%(levelname)s", "module": "%(module)s", "message": "%(message)s"}'
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": os.path.join(LOG_DIR, "gateway.log"),
            "maxBytes": 1024 * 1024 * 5,
            "backupCount": 5,
            "formatter": "verbose",
        },
        "security_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": os.path.join(LOG_DIR, "security.log"),
            "maxBytes": 1024 * 1024 * 2,
            "backupCount": 3,
            "formatter": "verbose",
            "level": "WARNING",
        },
        "performance_file": {
            "class": "logging.FileHandler",
            "filename": os.path.join(LOG_DIR, "performance.log"),
            "formatter": "performance",
        },
        "mail_admins": {
            "level": "ERROR",
            "class": "django.utils.log.AdminEmailHandler",
            "formatter": "verbose",
        },
        "json_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": os.path.join(LOG_DIR, "structured.log"),
            "maxBytes": 1024 * 1024 * 5,
            "backupCount": 3,
            "formatter": "json",
        },
        **({
            "syslog": {
                "class": "logging.handlers.SysLogHandler",
                "address": (SYSLOG_ADDRESS, SYSLOG_PORT),
                "formatter": "verbose",
                "facility": SysLogHandler.LOG_DAEMON,
            }
        } if SYSLOG_ADDRESS else {})
    },
    "loggers": {
        "django": {
            "handlers": ["console", "file", "mail_admins"] + (["syslog"] if SYSLOG_ADDRESS else []),
            "level": os.getenv("DJANGO_LOG_LEVEL", "INFO"),
            "propagate": True,
        },
        "django.security": {
            "handlers": ["security_file", "mail_admins"] + (["syslog"] if SYSLOG_ADDRESS else []),
            "level": "WARNING",
            "propagate": False,
        },
        "gateway": {
            "handlers": ["file", "json_file"] + (["syslog"] if SYSLOG_ADDRESS else []),
            "level": "INFO",
            "propagate": True,
        },
        "performance": {
            "handlers": ["performance_file"] + (["syslog"] if SYSLOG_ADDRESS else []),
            "level": "INFO",
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console", "file"] + (["syslog"] if SYSLOG_ADDRESS else []),
        "level": "WARNING",
    },
}
