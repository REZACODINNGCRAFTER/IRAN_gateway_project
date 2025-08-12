# security/ratelimit.py

import time
import logging
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from django.http import HttpRequest, JsonResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

class SimpleRateLimiter:
    """
    A simple in-memory rate limiter by IP address.
    Not suitable for production use with multiple workers or servers.
    """

    def __init__(self, limit: int = 100, window: int = 60):
        self.limit = limit  # Max requests per window
        self.window = window  # Time window in seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, ip: str) -> bool:
        self._cleanup_old_requests(ip)
        allowed = len(self.requests[ip]) < self.limit
        if allowed:
            self.requests[ip].append(time.time())
        return allowed

    def get_remaining_requests(self, ip: str) -> int:
        self._cleanup_old_requests(ip)
        return max(0, self.limit - len(self.requests[ip]))

    def get_reset_time(self, ip: str) -> float:
        if not self.requests[ip]:
            return 0.0
        now = time.time()
        oldest_request = min(self.requests[ip], default=now)
        return max(0.0, self.window - (now - oldest_request))

    def reset(self, ip: Optional[str] = None):
        if ip:
            self.requests.pop(ip, None)
        else:
            self.requests.clear()

    def _cleanup_old_requests(self, ip: str):
        window_start = time.time() - self.window
        self.requests[ip] = [req for req in self.requests[ip] if req > window_start]

    def get_usage_summary(self, ip: str) -> Dict[str, float]:
        self._cleanup_old_requests(ip)
        return {
            "limit": self.limit,
            "remaining": self.get_remaining_requests(ip),
            "reset_in": self.get_reset_time(ip)
        }

    def set_limit(self, limit: int):
        logger.info(f"Setting new rate limit: {limit}")
        self.limit = limit

    def set_window(self, window: int):
        logger.info(f"Setting new rate window: {window} seconds")
        self.window = window

rate_limiter = SimpleRateLimiter(limit=60, window=60)

class RateLimitMiddleware(MiddlewareMixin):
    """
    Django middleware to apply rate limiting to all views based on client IP.
    """

    def process_request(self, request: HttpRequest):
        ip = self.get_client_ip(request)
        if not rate_limiter.is_allowed(ip):
            remaining = rate_limiter.get_reset_time(ip)
            logger.warning(f"Rate limit exceeded for IP: {ip}")
            return JsonResponse(
                {"error": "Rate limit exceeded.", "retry_after": remaining},
                status=429
            )

    def get_client_ip(self, request: HttpRequest) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")

# Utility for manual checks and external management

def is_ip_allowed(ip: str) -> bool:
    return rate_limiter.is_allowed(ip)

def get_remaining_requests(ip: str) -> int:
    return rate_limiter.get_remaining_requests(ip)

def get_rate_limit_reset_time(ip: str) -> float:
    return rate_limiter.get_reset_time(ip)

def reset_rate_limit(ip: Optional[str] = None):
    rate_limiter.reset(ip)

def get_ip_usage_summary(ip: str) -> Dict[str, float]:
    return rate_limiter.get_usage_summary(ip)

def configure_rate_limit(limit: int, window: int):
    rate_limiter.set_limit(limit)
    rate_limiter.set_window(window)
    logger.info(f"Rate limit configured to {limit} requests per {window} seconds")
