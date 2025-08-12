"""
api_gateway/serializers.py

Contains serializers for authentication, user profiles, password change, health diagnostics,
API diagnostics, and extended system feedback for observability.
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class JWTLoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        data['username'] = self.user.username
        data['email'] = self.user.email
        return data


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name', 'is_active',
        )


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])

    def validate_old_password(self, value):
        user = self.context['user']
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is not correct")
        return value

    def save(self, **kwargs):
        user = self.context['user']
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class HealthStatusSerializer(serializers.Serializer):
    status = serializers.CharField()
    timestamp = serializers.DateTimeField()


class VersionInfoSerializer(serializers.Serializer):
    version = serializers.CharField()
    framework = serializers.CharField()
    python = serializers.CharField()
    build_hash = serializers.CharField(required=False)


class IPReputationSerializer(serializers.Serializer):
    ip = serializers.IPAddressField()
    suspicious = serializers.BooleanField()
    country = serializers.CharField(required=False)
    last_seen = serializers.DateTimeField(required=False)


class FeatureFlagSerializer(serializers.Serializer):
    beta_features = serializers.BooleanField()
    maintenance_mode = serializers.BooleanField()
    dark_mode_enabled = serializers.BooleanField(default=False)


class SessionValidationSerializer(serializers.Serializer):
    valid_session = serializers.BooleanField()
    user_id = serializers.IntegerField()
    expires_at = serializers.DateTimeField(required=False)


class EnvVarSerializer(serializers.Serializer):
    env_vars = serializers.DictField(child=serializers.CharField())


class ActiveUsersCountSerializer(serializers.Serializer):
    active_users = serializers.IntegerField()
    guest_sessions = serializers.IntegerField(default=0)


class DebugHeadersSerializer(serializers.Serializer):
    headers = serializers.DictField(child=serializers.CharField())


class ServiceStatusSerializer(serializers.Serializer):
    service_name = serializers.CharField()
    status = serializers.ChoiceField(choices=[('OK', 'OK'), ('FAIL', 'FAIL'), ('WARN', 'WARN')])
    message = serializers.CharField(allow_blank=True, required=False)
    last_checked = serializers.DateTimeField()


class RateLimitStatusSerializer(serializers.Serializer):
    scope = serializers.CharField()
    remaining = serializers.IntegerField()
    reset_in = serializers.DurationField()


class DatabaseHealthSerializer(serializers.Serializer):
    connection = serializers.CharField()
    latency_ms = serializers.FloatField()
    replica_lag = serializers.FloatField(required=False)


class CacheStatusSerializer(serializers.Serializer):
    backend = serializers.CharField()
    available = serializers.BooleanField()
    hit_rate = serializers.FloatField(required=False)
    eviction_count = serializers.IntegerField(default=0)


class NotificationPreferenceSerializer(serializers.Serializer):
    email_alerts = serializers.BooleanField()
    sms_alerts = serializers.BooleanField()
    push_notifications = serializers.BooleanField()


class AuditLogEntrySerializer(serializers.Serializer):
    event_type = serializers.CharField()
    actor = serializers.CharField()
    target = serializers.CharField(required=False)
    timestamp = serializers.DateTimeField()
    metadata = serializers.JSONField(required=False)


class ServiceDependencySerializer(serializers.Serializer):
    dependency = serializers.CharField()
    healthy = serializers.BooleanField()
    response_time_ms = serializers.FloatField()


class ErrorTraceSerializer(serializers.Serializer):
    service = serializers.CharField()
    error_message = serializers.CharField()
    stack_trace = serializers.CharField()
    timestamp = serializers.DateTimeField()


class TokenUsageSerializer(serializers.Serializer):
    token_type = serializers.CharField()
    used = serializers.BooleanField()
    issued_at = serializers.DateTimeField()
    expires_at = serializers.DateTimeField()


class LoginAuditSerializer(serializers.Serializer):
    username = serializers.CharField()
    login_time = serializers.DateTimeField()
    ip_address = serializers.IPAddressField()
    successful = serializers.BooleanField()
    user_agent = serializers.CharField(required=False)


class RoleAssignmentSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    role = serializers.CharField()
    assigned_by = serializers.CharField()
    assigned_at = serializers.DateTimeField()


class UsageStatsSerializer(serializers.Serializer):
    endpoint = serializers.CharField()
    call_count = serializers.IntegerField()
    average_latency = serializers.FloatField()
    status_code_distribution = serializers.JSONField()


class SecurityAlertSerializer(serializers.Serializer):
    alert_type = serializers.CharField()
    severity = serializers.ChoiceField(choices=[('LOW', 'LOW'), ('MEDIUM', 'MEDIUM'), ('HIGH', 'HIGH')])
    description = serializers.CharField()
    detected_at = serializers.DateTimeField()
    resolved = serializers.BooleanField(default=False)


class SystemResourceUsageSerializer(serializers.Serializer):
    cpu_percent = serializers.FloatField()
    memory_percent = serializers.FloatField()
    disk_usage = serializers.FloatField()
    uptime_seconds = serializers.IntegerField()


class SystemEventSerializer(serializers.Serializer):
    event_id = serializers.CharField()
    level = serializers.ChoiceField(choices=[('INFO', 'INFO'), ('WARNING', 'WARNING'), ('ERROR', 'ERROR')])
    source = serializers.CharField()
    message = serializers.CharField()
    timestamp = serializers.DateTimeField()


class APIKeySerializer(serializers.Serializer):
    key_id = serializers.CharField()
    name = serializers.CharField()
    created_at = serializers.DateTimeField()
    expires_at = serializers.DateTimeField(required=False)
    is_active = serializers.BooleanField()


class GeoLocationSerializer(serializers.Serializer):
    ip_address = serializers.IPAddressField()
    country = serializers.CharField()
    city = serializers.CharField(required=False)
    latitude = serializers.FloatField()
    longitude = serializers.FloatField()
