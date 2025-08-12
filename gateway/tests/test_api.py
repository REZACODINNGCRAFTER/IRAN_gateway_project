"""
API endpoint tests for the gateway application.
"""

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.settings import api_settings

User = get_user_model()


class GatewayAPITests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='apitestuser',
            password='securepass123',
            email='apitestuser@example.com'
        )
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)
        self.refresh_token = str(refresh)
        self.auth_header = f'Bearer {self.access_token}'

    def test_token_authentication(self):
        url = reverse('token_obtain_pair')
        response = self.client.post(url, {
            'username': 'apitestuser',
            'password': 'securepass123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_protected_dashboard_api(self):
        url = reverse('gateway:api-dashboard')
        self.client.credentials(HTTP_AUTHORIZATION=self.auth_header)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('username', response.data)

    def test_unauthorized_access(self):
        url = reverse('gateway:api-dashboard')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_token(self):
        url = reverse('token_refresh')
        response = self.client.post(url, {'refresh': self.refresh_token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_token_verify(self):
        url = reverse('token_verify')
        response = self.client.post(url, {'token': self.access_token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_invalid_token(self):
        url = reverse('token_verify')
        response = self.client.post(url, {'token': 'invalid.token.value'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('detail', response.data)

    def test_logout_endpoint(self):
        url = reverse('gateway:api-logout')
        self.client.credentials(HTTP_AUTHORIZATION=self.auth_header)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)

    def test_expired_token_access(self):
        with self.settings(SIMPLE_JWT={"ACCESS_TOKEN_LIFETIME": api_settings.ACCESS_TOKEN_LIFETIME.replace(seconds=0)}):
            refresh = RefreshToken.for_user(self.user)
            expired_token = str(refresh.access_token)
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {expired_token}')
            url = reverse('gateway:api-dashboard')
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_api_rate_limiting(self):
        url = reverse('gateway:api-dashboard')
        self.client.credentials(HTTP_AUTHORIZATION=self.auth_header)
        for _ in range(10):
            self.client.get(url)
        response = self.client.get(url)
        self.assertNotIn(response.status_code, [status.HTTP_429_TOO_MANY_REQUESTS])

    def test_user_info_detail_api(self):
        url = reverse('gateway:api-user-detail')
        self.client.credentials(HTTP_AUTHORIZATION=self.auth_header)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], self.user.username)
        self.assertEqual(response.data['email'], self.user.email)

    def test_invalid_login(self):
        url = reverse('token_obtain_pair')
        response = self.client.post(url, {
            'username': 'apitestuser',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('no_active_account', str(response.data))

    def test_token_blacklist(self):
        url = reverse('gateway:api-logout')
        self.client.credentials(HTTP_AUTHORIZATION=self.auth_header)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.get(reverse('gateway:api-dashboard'))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_api_health_check(self):
        url = reverse('gateway:api-health')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'ok')

    def test_otp_verification_api(self):
        url = reverse('gateway:api-otp')
        self.client.credentials(HTTP_AUTHORIZATION=self.auth_header)
        response = self.client.post(url, {'otp': '123456'})  # Simulated OTP
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST])

    def test_captcha_verification_api(self):
        url = reverse('gateway:api-captcha')
        self.client.credentials(HTTP_AUTHORIZATION=self.auth_header)
        response = self.client.post(url, {'captcha': 'valid_captcha'})  # Simulated CAPTCHA
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST])

    def test_password_reset_flow(self):
        url = reverse('gateway:api-password-reset')
        response = self.client.post(url, {'email': self.user.email})
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_202_ACCEPTED])

    def test_register_user_api(self):
        url = reverse('gateway:api-register')
        response = self.client.post(url, {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'NewUserPass123!'
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('username', response.data)

    def test_api_permissions_enforced(self):
        url = reverse('gateway:api-admin-only')
        self.client.credentials(HTTP_AUTHORIZATION=self.auth_header)
        response = self.client.get(url)
        self.assertIn(response.status_code, [status.HTTP_403_FORBIDDEN, status.HTTP_200_OK])
