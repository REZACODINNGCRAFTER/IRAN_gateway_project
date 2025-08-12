from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.user_register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('preferences/', views.preferences_view, name='preferences'),
    path('deactivate/', views.deactivate_account, name='deactivate'),
    path('role-update/', views.update_user_role, name='role_update'),
    path('2fa/enable/', views.enable_2fa, name='enable_2fa'),
    path('2fa/verify/', views.verify_2fa, name='verify_2fa'),
    path('consent/', views.submit_user_consent, name='user_consent'),

    # Password reset workflow
    path('password-reset/', auth_views.PasswordResetView.as_view(template_name='accounts/password_reset.html'), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='accounts/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='accounts/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='accounts/password_reset_complete.html'), name='password_reset_complete'),

    # Extended endpoints
    path('email/verify/', views.email_verification_view, name='email_verification'),
    path('security/questions/', views.security_questions_view, name='security_questions'),
    path('activity/log/', views.user_activity_log_view, name='activity_log'),
    path('api/token/refresh/', views.api_token_refresh_view, name='api_token_refresh'),
    path('notifications/settings/', views.notification_settings_view, name='notification_settings'),

    # New advanced endpoints
    path('sessions/', views.session_history_view, name='session_history'),
    path('devices/manage/', views.device_management_view, name='device_management'),
    path('privacy/policy/', views.privacy_policy_view, name='privacy_policy'),
    path('terms-of-use/', views.terms_of_use_view, name='terms_of_use'),
    path('login-attempts/', views.login_attempts_view, name='login_attempts'),
    path('mfa/settings/', views.mfa_settings_view, name='mfa_settings'),
    path('account/export/', views.export_account_data, name='export_account_data'),
    path('account/delete/', views.delete_account_request, name='delete_account'),
]
