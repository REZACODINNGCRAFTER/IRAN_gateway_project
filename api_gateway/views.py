"""
api_gateway/views.py

Defines the view logic for API endpoints such as authentication, diagnostics, and security introspection.
"""

from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth.models import User
from django.utils.timezone import now
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.conf import settings

from .serializers import (
    JWTLoginSerializer,
    UserProfileSerializer,
    ChangePasswordSerializer,
    HealthStatusSerializer,
    VersionInfoSerializer,
)

import platform
import datetime
import socket
import os
import psutil
import uuid

class JWTLoginView(TokenObtainPairView):
    serializer_class = JWTLoginSerializer

class JWTRefreshView(TokenRefreshView):
    pass

class JWTLogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response({"detail": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)

class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={"user": request.user})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Password changed successfully."})

class HealthCheckView(APIView):
    def get(self, request):
        return Response({"status": "ok", "timestamp": now()})

class RateLimitStatusView(APIView):
    def get(self, request):
        return Response({"limit": "100/min", "remaining": 75})

class VersionInfoView(APIView):
    def get(self, request):
        return Response({
            "version": "1.0.0",
            "framework": "Django",
            "python": platform.python_version(),
        })

class UptimeStatusView(APIView):
    def get(self, request):
        uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())
        return Response({"uptime": str(uptime)})

class SystemStatusDetailView(APIView):
    def get(self, request):
        return Response({
            "cpu_percent": psutil.cpu_percent(),
            "memory": psutil.virtual_memory()._asdict(),
            "disk": psutil.disk_usage('/')._asdict()
        })

class EmailVerificationRequestView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        site = get_current_site(request).domain
        token = str(uuid.uuid4())
        verification_link = f"https://{site}/verify-email/{token}/"

        send_mail(
            subject="Verify your email",
            message=f"Click the link to verify your email: {verification_link}",
            from_email="no-reply@example.com",
            recipient_list=[user.email],
            fail_silently=False,
        )
        return Response({"detail": "Verification email sent."})

class SecurityAuditView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        return Response({"events": ["Login success", "Logout", "Token refreshed"]})

class ThrottleDebugView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        return Response({"active_rules": ["UserRateThrottle", "AnonRateThrottle"]})

class IPReputationCheckView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        ip = request.data.get("ip")
        is_suspicious = ip.startswith("192.168")
        return Response({"ip": ip, "suspicious": is_suspicious})

class APIDocumentationView(APIView):
    def get(self, request):
        return Response({"docs": "https://api.example.com/docs"})

class EndpointListView(APIView):
    def get(self, request):
        return Response({"endpoints": ["/auth/login/", "/auth/logout/", "/health/"]})

class OpenAPISchemaView(APIView):
    def get(self, request):
        return Response({"schema_url": "https://api.example.com/schema/openapi.yaml"})

class HostnameInfoView(APIView):
    def get(self, request):
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return Response({"hostname": hostname, "ip_address": ip_address})

class FeatureFlagView(APIView):
    def get(self, request):
        flags = {"beta_features": True, "maintenance_mode": False}
        return Response(flags)

class SessionValidationView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({"valid_session": True, "user_id": request.user.id})

class ServerEnvVarsView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        return Response({"env_vars": dict(os.environ)})

class ActiveUsersCountView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        count = User.objects.filter(is_active=True).count()
        return Response({"active_users": count})

class DebugHeadersEchoView(APIView):
    def get(self, request):
        return Response({"headers": dict(request.headers)})

class MaintenanceStatusView(APIView):
    def get(self, request):
        return Response({"maintenance": settings.MAINTENANCE_MODE if hasattr(settings, 'MAINTENANCE_MODE') else False})

class TokenBlacklistStatusView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        return Response({"blacklist_enabled": hasattr(settings, 'SIMPLE_JWT') and settings.SIMPLE_JWT.get("BLACKLIST_AFTER_ROTATION", False)})
