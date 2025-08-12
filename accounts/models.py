"""
accounts/models.py
Defines models for user accounts, roles, permissions,
and activity logging in the gateway authentication system.
"""

from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
import uuid

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(_('email address'), unique=True)
    first_name = models.CharField(_('first name'), max_length=30)
    last_name = models.CharField(_('last name'), max_length=150)
    is_email_verified = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(null=True, blank=True)
    is_locked = models.BooleanField(default=False)
    two_factor_enabled = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def lock_account(self):
        self.is_locked = True
        self.save(update_fields=['is_locked'])

    def unlock_account(self):
        self.is_locked = False
        self.save(update_fields=['is_locked'])

    def update_last_activity(self):
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])

    def is_recently_active(self):
        if self.last_activity:
            return (timezone.now() - self.last_activity).total_seconds() < 3600
        return False

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def has_role(self, role_name):
        return self.roles.filter(name=role_name).exists()

class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name

class UserRole(models.Model):
    user = models.ForeignKey(CustomUser, related_name="roles", on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'role')
        verbose_name = 'User Role'
        verbose_name_plural = 'User Roles'

    def __str__(self):
        return f"{self.user.email} - {self.role.name}"

class LoginAudit(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    successful = models.BooleanField(default=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Login {'Success' if self.successful else 'Fail'}: {self.user} @ {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']

class FailedLoginAttempt(models.Model):
    email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    attempt_count = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f"Failed login attempt for {self.email} from {self.ip_address}"

    def increment(self):
        self.attempt_count += 1
        self.timestamp = timezone.now()
        self.save(update_fields=['attempt_count', 'timestamp'])

class EmailVerificationToken(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f"Token for {self.user.email} - {'Used' if self.is_used else 'Unused'}"

    def mark_as_used(self):
        self.is_used = True
        self.save(update_fields=['is_used'])

class PasswordResetToken(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f"ResetToken for {self.user.email} - {'Used' if self.is_used else 'Unused'}"

    def mark_as_used(self):
        self.is_used = True
        self.save(update_fields=['is_used'])

    def is_expired(self):
        return (timezone.now() - self.created_at).total_seconds() > 3600

class UserSession(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_active_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Session for {self.user.email} ({self.session_key})"

    def terminate(self):
        self.delete()

    def is_expired(self, timeout=3600):
        return (timezone.now() - self.last_active_at).total_seconds() > timeout

class UserPreference(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='preferences')
    language = models.CharField(max_length=10, default='en')
    timezone = models.CharField(max_length=50, default='UTC')
    receive_newsletters = models.BooleanField(default=False)

    def __str__(self):
        return f"Preferences for {self.user.email}"

class AccountActivityLog(models.Model):
    ACTION_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('update_profile', 'Update Profile'),
        ('change_password', 'Change Password'),
        ('enable_2fa', 'Enable 2FA'),
        ('disable_2fa', 'Disable 2FA'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    description = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.email} - {self.action} at {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']
