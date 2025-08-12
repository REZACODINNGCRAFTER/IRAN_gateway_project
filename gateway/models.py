"""
Models for the Gateway app.
Includes login auditing, IP blacklisting, 2FA token tracking,
suspicious activity logging, session fingerprinting, login rate monitoring,
and enhanced session trust scoring.
"""

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from ipaddress import ip_address as ip_parse

User = get_user_model()

class LoginAudit(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    success = models.BooleanField(default=True)
    location = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Login Audit"
        verbose_name_plural = "Login Audits"

    def __str__(self):
        return f"{self.user} - {'Success' if self.success else 'Failure'} @ {self.timestamp}"

    def is_from_blacklisted_ip(self):
        return IPBlacklist.objects.filter(ip_address=self.ip_address, is_active=True).exists()


class IPBlacklist(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField(blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Blacklisted IP"
        verbose_name_plural = "Blacklisted IPs"

    def __str__(self):
        return self.ip_address

    def is_ipv6(self):
        return ip_parse(self.ip_address).version == 6

    def deactivate(self):
        self.is_active = False
        self.save()


class OTPToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "OTP Token"
        verbose_name_plural = "OTP Tokens"
        indexes = [
            models.Index(fields=['user', 'token']),
        ]

    def __str__(self):
        return f"{self.user} - {self.token} ({'Used' if self.is_used else 'Unused'})"

    def is_expired(self):
        return self.expires_at and timezone.now() > self.expires_at

    def mark_used(self):
        self.is_used = True
        self.save()


class SuspiciousEvent(models.Model):
    event_type = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True)

    class Meta:
        verbose_name = "Suspicious Event"
        verbose_name_plural = "Suspicious Events"
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.event_type} from {self.ip_address} @ {self.timestamp}"


class SessionFingerprint(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    fingerprint = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    device_info = models.CharField(max_length=255, blank=True, null=True)
    trusted = models.BooleanField(default=False)

    class Meta:
        unique_together = ('user', 'fingerprint')
        verbose_name = "Session Fingerprint"
        verbose_name_plural = "Session Fingerprints"

    def __str__(self):
        return f"{self.user} - {self.fingerprint}"

    def mark_trusted(self):
        self.trusted = True
        self.save()

    def is_recent(self, minutes=30):
        return (timezone.now() - self.last_seen).total_seconds() < minutes * 60


class LoginRateLimit(models.Model):
    ip_address = models.GenericIPAddressField()
    attempts = models.PositiveIntegerField(default=0)
    window_start = models.DateTimeField(auto_now_add=True)
    is_locked = models.BooleanField(default=False)
    lock_expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Login Rate Limit"
        verbose_name_plural = "Login Rate Limits"
        indexes = [
            models.Index(fields=['ip_address']),
        ]

    def __str__(self):
        return f"{self.ip_address} - {self.attempts} attempt(s)"

    def is_currently_locked(self):
        return self.is_locked and self.lock_expires_at and timezone.now() < self.lock_expires_at

    def reset_attempts(self):
        self.attempts = 0
        self.is_locked = False
        self.lock_expires_at = None
        self.save()

    def lock(self, duration_minutes=15):
        self.is_locked = True
        self.lock_expires_at = timezone.now() + timezone.timedelta(minutes=duration_minutes)
        self.save()
