from rest_framework import serializers
from django.contrib.auth import get_user_model
from gateway.models import LoginAudit

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "is_active"]


class LoginAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginAudit
        fields = ["id", "user", "ip_address", "user_agent", "timestamp", "status"]


class LoginRequestSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)


class OTPVerificationSerializer(serializers.Serializer):
    otp_code = serializers.CharField(max_length=6)
    session_token = serializers.CharField(max_length=255)


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()


class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class ContactFormSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    message = serializers.CharField(style={'base_template': 'textarea.html'})


class RegistrationSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]


class EmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)


class DeviceRegistrationSerializer(serializers.Serializer):
    device_id = serializers.CharField(max_length=255)
    device_type = serializers.ChoiceField(choices=[("android", "Android"), ("ios", "iOS"), ("web", "Web")])


class TwoFactorAuthSetupSerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=[("sms", "SMS"), ("email", "Email"), ("auth_app", "Authenticator App")])
    destination = serializers.CharField(max_length=255)


class DeactivateAccountSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    confirm = serializers.BooleanField()


class FeedbackSerializer(serializers.Serializer):
    rating = serializers.IntegerField(min_value=1, max_value=5)
    comments = serializers.CharField(required=False, allow_blank=True, style={'base_template': 'textarea.html'})


class AdminBroadcastSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=150)
    message = serializers.CharField(style={'base_template': 'textarea.html'})
    target_group = serializers.ChoiceField(choices=[("all", "All Users"), ("staff", "Staff Only"), ("premium", "Premium Members")])


class SessionLogSerializer(serializers.Serializer):
    session_key = serializers.CharField()
    ip_address = serializers.IPAddressField()
    user_agent = serializers.CharField()
    login_time = serializers.DateTimeField()
    logout_time = serializers.DateTimeField(required=False, allow_null=True)


class MFAChallengeSerializer(serializers.Serializer):
    challenge_id = serializers.UUIDField()
    challenge_type = serializers.ChoiceField(choices=[("email", "Email"), ("sms", "SMS"), ("push", "Push Notification")])
    status = serializers.ChoiceField(choices=[("pending", "Pending"), ("verified", "Verified"), ("failed", "Failed")])


class CAPTCHAValidationSerializer(serializers.Serializer):
    captcha_token = serializers.CharField()
    user_input = serializers.CharField(max_length=10)


class IPReputationCheckSerializer(serializers.Serializer):
    ip_address = serializers.IPAddressField()
    score = serializers.IntegerField()
    threat_level = serializers.ChoiceField(choices=[("low", "Low"), ("medium", "Medium"), ("high", "High")])
