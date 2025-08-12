"""
Forms for the Gateway app.
Includes login, OTP verification, CAPTCHA validation, password reset,
user profile update, email verification, change password, and consent agreement forms.
"""

from django import forms
from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.conf import settings
from django.contrib.auth.forms import (
    PasswordResetForm as DjangoPasswordResetForm,
    SetPasswordForm as DjangoSetPasswordForm,
    PasswordChangeForm as DjangoPasswordChangeForm,
)

User = get_user_model()

class LoginForm(forms.Form):
    username = forms.CharField(max_length=150, label=_("Username"))
    password = forms.CharField(widget=forms.PasswordInput, label=_("Password"))
    remember_me = forms.BooleanField(required=False, label=_("Remember me"))

    def __init__(self, *args, **kwargs):
        self.user = None
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get("username")
        password = cleaned_data.get("password")

        if username and password:
            self.user = authenticate(username=username, password=password)
            if self.user is None:
                raise ValidationError(_("Invalid username or password"))
            elif not self.user.is_active:
                raise ValidationError(_("This account is inactive."))

        return cleaned_data

    def get_user(self):
        return self.user


class OTPForm(forms.Form):
    token = forms.CharField(max_length=6, label=_("One-Time Password"))

    def clean_token(self):
        token = self.cleaned_data.get("token")
        if not token or not token.isdigit() or len(token) != 6:
            raise ValidationError(_("Invalid OTP token."))
        return token


class CaptchaForm(forms.Form):
    captcha = forms.CharField(label=_("CAPTCHA"))

    def clean_captcha(self):
        captcha_input = self.cleaned_data.get("captcha")
        if not self._verify_captcha(captcha_input):
            raise ValidationError(_("Incorrect CAPTCHA response."))
        return captcha_input

    def _verify_captcha(self, value):
        # Dummy logic for demonstration; replace with actual CAPTCHA backend.
        return value.lower() == "human"


class PasswordResetRequestForm(DjangoPasswordResetForm):
    email = forms.EmailField(label=_("Email"), max_length=254)


class SetNewPasswordForm(DjangoSetPasswordForm):
    new_password1 = forms.CharField(
        label=_("New password"),
        widget=forms.PasswordInput,
        strip=False,
    )
    new_password2 = forms.CharField(
        label=_("Confirm new password"),
        widget=forms.PasswordInput,
        strip=False,
    )


class ProfileUpdateForm(forms.ModelForm):
    first_name = forms.CharField(max_length=30, required=False, label=_("First name"))
    last_name = forms.CharField(max_length=30, required=False, label=_("Last name"))
    email = forms.EmailField(label=_("Email"))

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]


class EmailVerificationForm(forms.Form):
    verification_code = forms.CharField(max_length=6, label=_("Verification Code"))

    def clean_verification_code(self):
        code = self.cleaned_data.get("verification_code")
        if not code or len(code) != 6 or not code.isalnum():
            raise ValidationError(_("Invalid verification code."))
        return code


class PasswordChangeForm(DjangoPasswordChangeForm):
    old_password = forms.CharField(
        label=_("Old password"),
        strip=False,
        widget=forms.PasswordInput,
    )
    new_password1 = forms.CharField(
        label=_("New password"),
        widget=forms.PasswordInput,
        strip=False,
    )
    new_password2 = forms.CharField(
        label=_("Confirm new password"),
        widget=forms.PasswordInput,
        strip=False,
    )


class ConsentAgreementForm(forms.Form):
    agree = forms.BooleanField(
        label=_("I agree to the terms and privacy policy."),
        required=True
    )
