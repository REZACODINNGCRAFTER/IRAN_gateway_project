"""
api_gateway/urls.py

This file defines URL routing for API gateway endpoints such as auth, status, and throttled resources.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from api_gateway import views

router = DefaultRouter()
# Example usage for additional APIs:
# router.register(r'users', views.UserViewSet, basename='user')
# router.register(r'logs', views.AuditLogViewSet, basename='audit-log')
# router.register(r'tokens', views.TokenManagementViewSet, basename='token')
# router.register(r'sessions', views.SessionViewSet, basename='session')
# router.register(r'notifications', views.NotificationViewSet, basename='notification')

urlpatterns = [
    # Authentication endpoints
    path('auth/login/', views.JWTLoginView.as_view(), name='api-login'),
    path('auth/refresh/', views.JWTRefreshView.as_view(), name='api-token-refresh'),
    path('auth/logout/', views.JWTLogoutView.as_view(), name='api-logout'),
    path('auth/profile/', views.UserProfileView.as_view(), name='api-user-profile'),
    path('auth/change-password/', views.ChangePasswordView.as_view(), name='api-change-password'),
    path('auth/verify-email/', views.VerifyEmailView.as_view(), name='api-verify-email'),
    path('auth/request-reset/', views.PasswordResetRequestView.as_view(), name='api-password-reset-request'),
    path('auth/reset-password/', views.PasswordResetConfirmView.as_view(), name='api-password-reset-confirm'),

    # Health and diagnostics
    path('health/', views.HealthCheckView.as_view(), name='api-health-check'),
    path('rate-limit-status/', views.RateLimitStatusView.as_view(), name='rate-limit-status'),
    path('version/', views.VersionInfoView.as_view(), name='api-version-info'),
    path('uptime/', views.UptimeStatusView.as_view(), name='api-uptime'),
    path('status/detail/', views.SystemStatusDetailView.as_view(), name='api-system-status-detail'),
    path('status/summary/', views.StatusSummaryView.as_view(), name='api-status-summary'),

    # Throttling debug and security introspection
    path('throttle/debug/', views.ThrottleDebugView.as_view(), name='api-throttle-debug'),
    path('security/audit/', views.SecurityAuditView.as_view(), name='api-security-audit'),
    path('security/ip-check/', views.IPReputationCheckView.as_view(), name='api-ip-check'),
    path('security/fingerprint/', views.ClientFingerprintView.as_view(), name='api-client-fingerprint'),

    # Notifications and messaging
    path('notifications/unread/', views.UnreadNotificationsView.as_view(), name='api-notifications-unread'),
    path('notifications/all/', views.AllNotificationsView.as_view(), name='api-notifications-all'),

    # API docs and metadata
    path('docs/', views.APIDocumentationView.as_view(), name='api-docs'),
    path('meta/endpoints/', views.EndpointListView.as_view(), name='api-endpoints'),
    path('meta/schema/', views.OpenAPISchemaView.as_view(), name='api-openapi-schema'),
    path('meta/info/', views.ProjectInfoView.as_view(), name='api-project-info'),

    # Include DRF router-registered views
    path('', include(router.urls)),
]
