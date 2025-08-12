"""
Views for the Gateway app.
Handles login, logout, OTP verification, dashboard, CAPTCHA fallback,
password reset, email verification, profile update, terms agreement,
and user activity logging.
"""

from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.utils.translation import gettext_lazy as _
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.utils.timezone import now
from django.http import JsonResponse

from .forms import (
    LoginForm, OTPForm, CaptchaForm,
    PasswordResetRequestForm, SetNewPasswordForm,
    EmailVerificationForm, ProfileUpdateForm, ConsentAgreementForm
)
from .models import OTPToken

@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.user.is_authenticated:
        return redirect("gateway:dashboard")

    form = LoginForm(request.POST or None)
    if form.is_valid():
        user = form.get_user()
        login(request, user)
        request.session["otp_verified"] = False
        return redirect("gateway:otp_verify")

    return render(request, "gateway/login.html", {"form": form})


@require_http_methods(["GET", "POST"])
@login_required
def otp_verify_view(request):
    if request.session.get("otp_verified"):
        return redirect("gateway:dashboard")

    form = OTPForm(request.POST or None)
    if form.is_valid():
        token = form.cleaned_data["token"]
        otp_match = OTPToken.objects.filter(user=request.user, token=token, is_used=False).first()
        if otp_match and not otp_match.is_expired():
            otp_match.mark_used()
            request.session["otp_verified"] = True
            return redirect("gateway:dashboard")
        messages.error(request, _("Invalid or expired OTP token."))

    return render(request, "gateway/otp_verify.html", {"form": form})


@login_required
def dashboard_view(request):
    return render(request, "gateway/dashboard.html")


@login_required
def logout_view(request):
    logout(request)
    messages.success(request, _("You have been logged out."))
    return redirect(reverse("gateway:login"))


@require_http_methods(["GET", "POST"])
def captcha_fallback_view(request):
    form = CaptchaForm(request.POST or None)
    if form.is_valid():
        messages.success(request, _("CAPTCHA verified successfully."))
        return redirect("gateway:login")
    return render(request, "gateway/captcha.html", {"form": form})


@require_http_methods(["GET", "POST"])
def password_reset_request_view(request):
    form = PasswordResetRequestForm(request.POST or None)
    if form.is_valid():
        form.save(request=request)
        messages.success(request, _("Password reset email has been sent."))
        return redirect("gateway:login")
    return render(request, "gateway/password_reset_request.html", {"form": form})


@require_http_methods(["GET", "POST"])
def password_reset_confirm_view(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        form = SetNewPasswordForm(user, request.POST or None)
        if form.is_valid():
            form.save()
            messages.success(request, _("Your password has been set. You can now log in."))
            return redirect("gateway:login")
    else:
        form = None
        messages.error(request, _("The reset link is invalid or has expired."))

    return render(request, "gateway/password_reset_confirm.html", {"form": form})


@require_http_methods(["GET", "POST"])
@login_required
def email_verification_view(request):
    form = EmailVerificationForm(request.POST or None)
    if form.is_valid():
        # Dummy logic for demonstration; replace with actual verification check.
        code = form.cleaned_data["verification_code"]
        if code == "123456":
            messages.success(request, _("Email verified successfully."))
            return redirect("gateway:dashboard")
        else:
            messages.error(request, _("Invalid verification code."))

    return render(request, "gateway/email_verify.html", {"form": form})


@require_http_methods(["GET", "POST"])
@login_required
def profile_update_view(request):
    form = ProfileUpdateForm(request.POST or None, instance=request.user)
    if form.is_valid():
        form.save()
        messages.success(request, _("Profile updated successfully."))
        return redirect("gateway:dashboard")
    return render(request, "gateway/profile_update.html", {"form": form})


@require_http_methods(["GET", "POST"])
@login_required
def consent_view(request):
    form = ConsentAgreementForm(request.POST or None)
    if form.is_valid():
        request.session["consent_agreed"] = True
        messages.success(request, _("Consent recorded. Thank you."))
        return redirect("gateway:dashboard")
    return render(request, "gateway/consent.html", {"form": form})


@login_required
def user_activity_log_view(request):
    # Stub logic for user activity JSON API endpoint
    return JsonResponse({
        "user": request.user.username,
        "last_login": request.user.last_login,
        "current_time": now().isoformat(),
        "session_key": request.session.session_key,
    })
