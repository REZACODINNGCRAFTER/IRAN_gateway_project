"""
Django signal handlers for the Gateway application.
This module tracks and logs security-relevant events such as user login/logout,
failed login attempts, suspicious activities, user profile updates, audit trail records,
password changes, session activities, MFA events, permission changes, user deactivation reasons,
and suspicious IP login patterns.
"""

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed, password_change_done
from django.contrib.sessions.models import Session
from django.db.models.signals import post_save, pre_save, post_delete, m2m_changed
from django.dispatch import receiver
from django.utils.timezone import now
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    ip = request.META.get('REMOTE_ADDR')
    ua = request.META.get('HTTP_USER_AGENT', 'unknown')
    logger.info(f"LOGIN SUCCESS: {user.username} from IP {ip} with UA {ua}")
    request.session['last_login_time'] = now().isoformat()
    suspicious_ips = ['123.456.789.0']
    if ip in suspicious_ips:
        logger.warning(f"SUSPICIOUS LOGIN IP: {ip} for user {user.username}")


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    ip = request.META.get('REMOTE_ADDR')
    logger.info(f"LOGOUT: {user.username} from IP {ip}")


@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    ip = request.META.get('REMOTE_ADDR') if request else 'unknown'
    logger.warning(f"FAILED LOGIN for user: {credentials.get('username')} from IP: {ip}")


@receiver(post_save, sender=User)
def notify_admin_on_superuser_creation(sender, instance, created, **kwargs):
    if created and instance.is_superuser:
        logger.info(f"New superuser created: {instance.username}")
        send_mail(
            subject="New Superuser Created",
            message=f"Superuser {instance.username} was just created.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[admin[1] for admin in settings.ADMINS],
            fail_silently=True
        )


@receiver(pre_save, sender=User)
def log_user_profile_update(sender, instance, **kwargs):
    if instance.pk:
        try:
            original = User.objects.get(pk=instance.pk)
            changes = []
            for field in ['email', 'first_name', 'last_name']:
                original_value = getattr(original, field)
                new_value = getattr(instance, field)
                if original_value != new_value:
                    changes.append(f"{field} changed from '{original_value}' to '{new_value}'")
            if changes:
                logger.info(f"PROFILE UPDATE for {instance.username}: " + "; ".join(changes))
        except User.DoesNotExist:
            pass


@receiver(password_change_done)
def log_password_change(sender, request, user, **kwargs):
    logger.info(f"PASSWORD CHANGE: {user.username} from IP {request.META.get('REMOTE_ADDR')}")


@receiver(post_save, sender=User)
def log_user_creation(sender, instance, created, **kwargs):
    if created and not instance.is_superuser:
        logger.info(f"New user registered: {instance.username} (Email: {instance.email})")


@receiver(post_delete, sender=User)
def log_user_deletion(sender, instance, **kwargs):
    logger.warning(f"USER DELETED: {instance.username} (Email: {instance.email})")


@receiver(post_save, sender=User)
def log_user_activation_change(sender, instance, **kwargs):
    try:
        original = User.objects.get(pk=instance.pk)
        if original.is_active != instance.is_active:
            status = "activated" if instance.is_active else "deactivated"
            reason = getattr(instance, 'deactivation_reason', 'Not specified')
            logger.info(f"ACCOUNT {status.upper()}: {instance.username}, Reason: {reason}")
    except User.DoesNotExist:
        pass


@receiver(post_save, sender=User)
def alert_on_admin_rights_change(sender, instance, **kwargs):
    try:
        original = User.objects.get(pk=instance.pk)
        if original.is_staff != instance.is_staff:
            if instance.is_staff:
                logger.info(f"Admin rights granted to user: {instance.username}")
            else:
                logger.info(f"Admin rights revoked from user: {instance.username}")
    except User.DoesNotExist:
        pass


@receiver(post_save, sender=Session)
def log_session_creation(sender, instance, created, **kwargs):
    if created:
        logger.info(f"SESSION CREATED: session key {instance.session_key} at {now().isoformat()}")


@receiver(post_delete, sender=Session)
def log_session_deletion(sender, instance, **kwargs):
    logger.info(f"SESSION DELETED: session key {instance.session_key} at {now().isoformat()}")


@receiver(m2m_changed, sender=User.groups.through)
def log_user_group_change(sender, instance, action, pk_set, **kwargs):
    if action in ['post_add', 'post_remove', 'post_clear']:
        logger.info(f"GROUP CHANGE: {instance.username} - Action: {action}, Groups affected: {pk_set}")


@receiver(m2m_changed, sender=User.user_permissions.through)
def log_user_permission_change(sender, instance, action, pk_set, **kwargs):
    if action in ['post_add', 'post_remove', 'post_clear']:
        logger.info(f"PERMISSION CHANGE: {instance.username} - Action: {action}, Permissions affected: {pk_set}")


@receiver(post_save, sender=User)
def alert_on_mfa_enabled(sender, instance, **kwargs):
    if hasattr(instance, 'mfa_enabled') and instance.mfa_enabled:
        logger.info(f"MFA ENABLED: {instance.username}")


@receiver(post_save, sender=User)
def alert_on_suspicious_email_change(sender, instance, **kwargs):
    suspicious_domains = ['example.ru', 'malicious.com']
    domain = instance.email.split('@')[-1]
    if domain in suspicious_domains:
        logger.warning(f"SUSPICIOUS EMAIL DOMAIN: {instance.username} updated to {instance.email}")


@receiver(pre_save, sender=User)
def enforce_email_domain_policy(sender, instance, **kwargs):
    allowed_domains = ['yourdomain.com']
    domain = instance.email.split('@')[-1]
    if domain not in allowed_domains:
        logger.warning(f"UNAPPROVED DOMAIN ATTEMPT: {instance.username} with email {instance.email}")
