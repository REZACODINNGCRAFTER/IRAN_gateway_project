"""
accounts/views.py
Handles user-related view logic: registration, login, logout, profile updates,
2FA, password resets, email verification, account settings, and more.
"""

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.views import PasswordResetConfirmView
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_POST

from .forms import (
    UserRegistrationForm, UserLoginForm, UserProfileUpdateForm,
    PasswordResetRequestForm, SetNewPasswordForm, TwoFactorEnableForm,
    TwoFactorVerifyForm, EmailVerificationForm, UserPreferenceForm,
    UserDeactivateForm, UserRoleUpdateForm, AvatarUploadForm,
    UserSecurityQuestionsForm, UserAgreementConsentForm
)
from .models import CustomUser


def user_register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, _('Registration successful. Please login.'))
            return redirect('accounts:login')
    else:
        form = UserRegistrationForm()
    return render(request, 'accounts/register.html', {'form': form})


def user_login(request):
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, email=email, password=password)
            if user:
                login(request, user)
                return redirect('dashboard')
            else:
                messages.error(request, _('Invalid credentials'))
    else:
        form = UserLoginForm()
    return render(request, 'accounts/login.html', {'form': form})


@login_required
def user_logout(request):
    logout(request)
    messages.info(request, _('You have been logged out.'))
    return redirect('accounts:login')


@login_required
def profile_view(request):
    if request.method == 'POST':
        profile_form = UserProfileUpdateForm(request.POST, instance=request.user)
        avatar_form = AvatarUploadForm(request.POST, request.FILES, instance=request.user)
        if profile_form.is_valid() and avatar_form.is_valid():
            profile_form.save()
            avatar_form.save()
            messages.success(request, _('Profile updated.'))
            return redirect('accounts:profile')
    else:
        profile_form = UserProfileUpdateForm(instance=request.user)
        avatar_form = AvatarUploadForm(instance=request.user)
    return render(request, 'accounts/profile.html', {
        'profile_form': profile_form,
        'avatar_form': avatar_form
    })


@login_required
def preferences_view(request):
    if request.method == 'POST':
        form = UserPreferenceForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, _('Preferences updated.'))
            return redirect('accounts:preferences')
    else:
        form = UserPreferenceForm(instance=request.user)
    return render(request, 'accounts/preferences.html', {'form': form})


@login_required
def deactivate_account(request):
    if request.method == 'POST':
        form = UserDeactivateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            logout(request)
            messages.warning(request, _('Account deactivated.'))
            return redirect('accounts:login')
    else:
        form = UserDeactivateForm(instance=request.user)
    return render(request, 'accounts/deactivate.html', {'form': form})


@login_required
def update_user_role(request):
    if request.method == 'POST':
        form = UserRoleUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, _('User role updated.'))
            return redirect('accounts:profile')
    else:
        form = UserRoleUpdateForm(instance=request.user)
    return render(request, 'accounts/role_update.html', {'form': form})


@login_required
def enable_2fa(request):
    if request.method == 'POST':
        form = TwoFactorEnableForm(request.POST)
        if form.is_valid():
            # Token generation logic placeholder
            messages.success(request, _('Two-factor authentication enabled.'))
            return redirect('accounts:profile')
    else:
        form = TwoFactorEnableForm()
    return render(request, 'accounts/2fa_enable.html', {'form': form})


@login_required
def verify_2fa(request):
    if request.method == 'POST':
        form = TwoFactorVerifyForm(request.POST)
        if form.is_valid():
            # Token verification logic placeholder
            messages.success(request, _('Two-factor verification successful.'))
            return redirect('dashboard')
    else:
        form = TwoFactorVerifyForm()
    return render(request, 'accounts/2fa_verify.html', {'form': form})


@login_required
def submit_user_consent(request):
    if request.method == 'POST':
        form = UserAgreementConsentForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, _('User agreement accepted.'))
            return redirect('dashboard')
    else:
        form = UserAgreementConsentForm(instance=request.user)
    return render(request, 'accounts/consent.html', {'form': form})


@login_required
def resend_email_verification(request):
    if request.method == 'POST':
        # Logic to resend email verification link (placeholder)
        messages.success(request, _('Verification email sent again.'))
        return redirect('accounts:profile')
    return HttpResponse(status=405)


@login_required
def set_security_questions(request):
    if request.method == 'POST':
        form = UserSecurityQuestionsForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, _('Security questions updated.'))
            return redirect('accounts:profile')
    else:
        form = UserSecurityQuestionsForm(instance=request.user)
    return render(request, 'accounts/security_questions.html', {'form': form})
