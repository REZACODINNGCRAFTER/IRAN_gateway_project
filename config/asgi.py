"""
ASGI config for the Django project.
Prepares the ASGI application for use with asynchronous servers and real-time communication.
Supports HTTP and WebSocket routing with Django Channels.
Includes diagnostics, error logging, and routing hooks.
"""

import os
import logging
import platform
import socket
from django.core.asgi import get_asgi_application

# Optional: Uncomment and configure for WebSocket support
# from channels.routing import ProtocolTypeRouter, URLRouter
# from channels.auth import AuthMiddlewareStack
# from gateway.routing import websocket_urlpatterns

logger = logging.getLogger("asgi")


def get_settings_module(default: str = "config.settings.dev") -> str:
    """
    Determine and return the Django settings module.
    """
    return os.getenv("DJANGO_SETTINGS_MODULE", default)


def log_environment_details():
    """
    Print platform and runtime diagnostics for visibility in ASGI logs.
    """
    logger.info("---- ASGI Runtime Info ----")
    logger.info(f"Host: {socket.gethostname()}")
    logger.info(f"Platform: {platform.system()} {platform.release()} [{platform.machine()}]")
    logger.info(f"Python: {platform.python_version()}")
    logger.info(f"Settings Module: {os.environ.get('DJANGO_SETTINGS_MODULE', 'Not Set')}")
    logger.info("---------------------------")


def initialize_asgi_application():
    """
    Initialize the core ASGI application with robust error handling.
    """
    try:
        app = get_asgi_application()
        logger.info("ASGI application initialized successfully.")
        return app
    except Exception as e:
        logger.exception("Failed to initialize ASGI application: %s", e)
        raise


def is_using_channels() -> bool:
    """
    Check if Django Channels is installed for potential routing.
    """
    try:
        import channels  # noqa: F401
        return True
    except ImportError:
        return False


# Initialize logging format
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Set the settings module dynamically
os.environ.setdefault("DJANGO_SETTINGS_MODULE", get_settings_module())
logger.info(f"Using settings module: {os.environ['DJANGO_SETTINGS_MODULE']}")

# Output environment details
log_environment_details()

# Initialize ASGI application
application = initialize_asgi_application()

# Optional: Future WebSocket routing setup
# if is_using_channels():
#     application = ProtocolTypeRouter({
#         "http": get_asgi_application(),
#         "websocket": AuthMiddlewareStack(
#             URLRouter(websocket_urlpatterns)
#         ),
#     })
