"""
URL configuration for the Gateway app.
Includes login/logout views, OTP verification, dashboard, security diagnostics,
user profile tools, administrative endpoints, and development utilities.
"""

from django.urls import path
from . import views

app_name = "gateway"

urlpatterns = [
    # Authentication & Session
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("otp/verify/", views.otp_verify_view, name="otp_verify"),
    path("2fa/reset/", views.reset_2fa_view, name="reset_2fa"),
    path("session/info/", views.session_info_view, name="session_info"),

    # Dashboard
    path("dashboard/", views.dashboard_view, name="dashboard"),

    # Security Tools
    path("ip/check/", views.ip_check_view, name="ip_check"),
    path("rate-limit/status/", views.rate_limit_status_view, name="rate_limit_status"),
    path("blacklist/toggle/", views.toggle_blacklist_view, name="toggle_blacklist"),
    path("security/events/", views.security_events_view, name="security_events"),
    path("security/audit/<str:event_id>/", views.audit_event_detail_view, name="audit_event_detail"),

    # System Monitoring
    path("healthz/", views.health_check_view, name="health_check"),
    path("audit/logs/", views.audit_log_view, name="audit_logs"),
    path("metrics/", views.metrics_view, name="metrics"),
    path("system/status/", views.system_status_view, name="system_status"),

    # User Utilities
    path("profile/", views.profile_view, name="profile"),
    path("activity/", views.activity_log_view, name="activity_log"),
    path("notifications/", views.notification_view, name="notifications"),
    path("preferences/", views.user_preferences_view, name="user_preferences"),

    # Maintenance
    path("maintenance/mode/", views.maintenance_mode_view, name="maintenance_mode"),
    path("feature/flags/", views.feature_flags_view, name="feature_flags"),
    path("tasks/trigger/", views.task_trigger_view, name="task_trigger"),

    # Development / Testing Utilities (optional)
    path("dev/ping/", views.dev_ping_view, name="dev_ping"),
    path("dev/error/", views.dev_error_view, name="dev_error"),
]
