"""
accounts/forms.py
Defines forms related to user registration, login, profile updates,
password reset functionality, and extended user actions in the authentication system.
"""

from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _

from .models import CustomUser


class UserRegistrationForm(forms.ModelForm):
    password1 = forms.CharField(label=_('Password'), widget=forms.PasswordInput)
    password2 = forms.CharField(label=_('Confirm Password'), widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ('email', 'first_name', 'last_name')

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(_('Passwords do not match'))
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user


class UserLoginForm(forms.Form):
    email = forms.EmailField(label=_('Email'))
    password = forms.CharField(label=_('Password'), widget=forms.PasswordInput)

    def clean(self):
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')
        if email and password:
            user = authenticate(email=email, password=password)
            if not user:
                raise forms.ValidationError(_('Invalid login credentials'))
            if not user.is_active:
                raise forms.ValidationError(_('This account is inactive'))
        return self.cleaned_data


class UserProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'email')


class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(label=_('Email'))


class SetNewPasswordForm(forms.Form):
    new_password1 = forms.CharField(label=_('New Password'), widget=forms.PasswordInput)
    new_password2 = forms.CharField(label=_('Confirm New Password'), widget=forms.PasswordInput)

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(_('Passwords do not match'))
        return password2


class TwoFactorEnableForm(forms.Form):
    token = forms.CharField(label=_('2FA Token'), max_length=6)


class TwoFactorVerifyForm(forms.Form):
    token = forms.CharField(label=_('Verification Token'), max_length=6)


class EmailVerificationForm(forms.Form):
    token = forms.CharField(label=_('Verification Token'), max_length=64)


class UserLockToggleForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ('is_locked',)
        labels = {
            'is_locked': _('Lock this account')
        }


class AdminUserCreationForm(forms.ModelForm):
    password1 = forms.CharField(label=_('Password'), widget=forms.PasswordInput)
    password2 = forms.CharField(label=_('Confirm Password'), widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ('email', 'first_name', 'last_name', 'is_staff', 'is_superuser')

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(_('Passwords do not match'))
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user


class UserDeactivateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['is_active']
        labels = {
            'is_active': _('Deactivate this account')
        }


class UserRoleUpdateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['role']
        labels = {
            'role': _('Update User Role')
        }


class UserPreferenceForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['language', 'timezone']
        labels = {
            'language': _('Preferred Language'),
            'timezone': _('Timezone')
        }


class UserNotificationSettingsForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['receive_newsletters', 'notify_login']
        labels = {
            'receive_newsletters': _('Receive Newsletters'),
            'notify_login': _('Notify on New Login')
        }


class AvatarUploadForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['avatar']
        labels = {
            'avatar': _('Upload Profile Picture')
        }


class UserSecurityQuestionsForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['security_question', 'security_answer']
        labels = {
            'security_question': _('Security Question'),
            'security_answer': _('Security Answer')
        }


class UserAgreementConsentForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['agreed_to_terms']
        labels = {
            'agreed_to_terms': _('I agree to the Terms and Conditions')
        }
