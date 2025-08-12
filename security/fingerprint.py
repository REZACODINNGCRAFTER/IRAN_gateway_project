# security/fingerprint.py

import hashlib
import json
from typing import Dict, Optional
from django.http import HttpRequest
from django.utils.crypto import get_random_string
from collections import Counter
import math
import logging

logger = logging.getLogger(__name__)

class FingerprintGenerator:
    """
    Generates and validates browser/device fingerprints
    based on request metadata.
    """

    def __init__(self, salt: Optional[str] = None):
        self.salt = salt or get_random_string(32)

    def generate_fingerprint(self, request: HttpRequest) -> str:
        """
        Generates a consistent fingerprint from request headers and IP.
        """
        data = self._collect_metadata(request)
        raw_string = json.dumps(data, sort_keys=True)
        fingerprint = hashlib.sha256(raw_string.encode("utf-8")).hexdigest()
        logger.debug(f"Generated fingerprint: {fingerprint}")
        return fingerprint

    def validate_fingerprint(self, request: HttpRequest, expected: str) -> bool:
        """
        Validates the current request fingerprint against the expected value.
        """
        current = self.generate_fingerprint(request)
        is_valid = current == expected
        logger.debug(f"Fingerprint validation: {is_valid}")
        return is_valid

    def _collect_metadata(self, request: HttpRequest) -> Dict[str, str]:
        return {
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            "accept": request.META.get("HTTP_ACCEPT", ""),
            "encoding": request.META.get("HTTP_ACCEPT_ENCODING", ""),
            "language": request.META.get("HTTP_ACCEPT_LANGUAGE", ""),
            "ip": self._get_ip_address(request),
            "referer": request.META.get("HTTP_REFERER", ""),
            "connection": request.META.get("HTTP_CONNECTION", ""),
            "host": request.META.get("HTTP_HOST", ""),
            "forwarded": request.META.get("HTTP_FORWARDED", ""),
            "user_agent_platform": request.META.get("HTTP_SEC_CH_UA_PLATFORM", ""),
            "user_agent_mobile": request.META.get("HTTP_SEC_CH_UA_MOBILE", ""),
            "cache_control": request.META.get("HTTP_CACHE_CONTROL", ""),
            "salt": self.salt,
        }

    def _get_ip_address(self, request: HttpRequest) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")

    def entropy_of_fingerprint(self, fingerprint: str) -> float:
        """
        Estimate the entropy (randomness) of a fingerprint string.
        """
        counter = Counter(fingerprint)
        total = len(fingerprint)
        entropy = -sum((count / total) * math.log2(count / total) for count in counter.values())
        logger.debug(f"Entropy of fingerprint: {entropy:.4f}")
        return entropy

    def summarize_fingerprint(self, fingerprint: str) -> Dict[str, str]:
        """
        Returns a brief summary of the fingerprint's metadata.
        """
        return {
            "length": str(len(fingerprint)),
            "starts_with": fingerprint[:6],
            "ends_with": fingerprint[-6:],
        }

    def is_suspicious_entropy(self, fingerprint: str, threshold: float = 3.5) -> bool:
        """
        Check if fingerprint entropy is suspiciously low (predictable).
        """
        entropy = self.entropy_of_fingerprint(fingerprint)
        is_suspicious = entropy < threshold
        logger.warning(f"Suspicious entropy detected: {entropy:.4f}") if is_suspicious else logger.debug(f"Entropy normal: {entropy:.4f}")
        return is_suspicious

    def get_browser_info(self, request: HttpRequest) -> Dict[str, str]:
        """
        Extracts minimal browser info from headers.
        """
        return {
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            "language": request.META.get("HTTP_ACCEPT_LANGUAGE", ""),
        }

    def compare_fingerprints(self, fp1: str, fp2: str) -> float:
        """
        Compares two fingerprints using Jaccard similarity.
        """
        set1, set2 = set(fp1), set(fp2)
        intersection = set1.intersection(set2)
        union = set1.union(set2)
        similarity = len(intersection) / len(union) if union else 0.0
        logger.debug(f"Jaccard similarity: {similarity:.4f}")
        return similarity

    def get_fingerprint_features(self, request: HttpRequest) -> Dict[str, str]:
        """
        Return raw fingerprint feature set before hashing.
        """
        return self._collect_metadata(request)

# Singleton instance
_fingerprint = FingerprintGenerator()

def generate_fingerprint(request: HttpRequest) -> str:
    return _fingerprint.generate_fingerprint(request)

def validate_fingerprint(request: HttpRequest, expected: str) -> bool:
    return _fingerprint.validate_fingerprint(request, expected)

def entropy_of_fingerprint(fingerprint: str) -> float:
    return _fingerprint.entropy_of_fingerprint(fingerprint)

def summarize_fingerprint(fingerprint: str) -> Dict[str, str]:
    return _fingerprint.summarize_fingerprint(fingerprint)

def is_suspicious_entropy(fingerprint: str, threshold: float = 3.5) -> bool:
    return _fingerprint.is_suspicious_entropy(fingerprint, threshold)

def get_browser_info(request: HttpRequest) -> Dict[str, str]:
    return _fingerprint.get_browser_info(request)

def compare_fingerprints(fp1: str, fp2: str) -> float:
    return _fingerprint.compare_fingerprints(fp1, fp2)

def get_fingerprint_features(request: HttpRequest) -> Dict[str, str]:
    return _fingerprint.get_fingerprint_features(request)
