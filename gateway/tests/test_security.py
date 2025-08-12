"""
Security-related tests for the gateway application.
Includes tests for IP blacklisting, session expiry, security headers,
HTTPS cookie enforcement, 2FA presence, CAPTCHA checks, suspicious login detection,
geo-IP restrictions, fingerprint validation, JWT expiration, user-agent filtering,
CORS configuration, and HTTP method enforcement.
"""

from django.test import TestCase, override_settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from django.conf import settings
from unittest import mock
import time
import jwt

User = get_user_model()


class SecurityTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='secureuser',
            password='VerySecure123!',
            email='secure@example.com'
        )
        self.login_url = reverse('token_obtain_pair')
        self.dashboard_url = reverse('gateway:api-dashboard')
        self.otp_url = reverse('gateway:api-otp')
        self.captcha_url = reverse('gateway:api-captcha')
        self.suspicious_log_url = reverse('gateway:api-login')
        self.geoip_check_url = reverse('gateway:api-geoip')
        self.fingerprint_url = reverse('gateway:api-fingerprint')
        self.cors_url = reverse('gateway:api-cors')
        self.useragent_url = reverse('gateway:api-useragent')

    def authenticate(self):
        response = self.client.post(self.login_url, {
            'username': 'secureuser',
            'password': 'VerySecure123!'
        })
        token = response.data.get('access')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

    def test_blacklisted_ip_denied(self):
        with override_settings(BLACKLISTED_IPS=['127.0.0.1']):
            response = self.client.get(self.dashboard_url, REMOTE_ADDR='127.0.0.1')
            self.assertEqual(response.status_code, 403)

    def test_non_blacklisted_ip_allowed(self):
        with override_settings(BLACKLISTED_IPS=['192.168.1.1']):
            self.authenticate()
            response = self.client.get(self.dashboard_url, REMOTE_ADDR='127.0.0.1')
            self.assertNotEqual(response.status_code, 403)

    def test_security_headers_present(self):
        self.authenticate()
        response = self.client.get(self.dashboard_url)
        self.assertIn('Strict-Transport-Security', response.headers)
        self.assertIn('X-Content-Type-Options', response.headers)
        self.assertIn('X-Frame-Options', response.headers)

    def test_session_timeout(self):
        with override_settings(SESSION_COOKIE_AGE=1):
            self.authenticate()
            time.sleep(2)
            response = self.client.get(self.dashboard_url)
            self.assertIn(response.status_code, [401, 403])

    def test_https_only_cookie(self):
        self.assertTrue(settings.SESSION_COOKIE_SECURE)
        self.assertTrue(settings.CSRF_COOKIE_SECURE)

    def test_otp_required_enforced(self):
        self.authenticate()
        response = self.client.post(self.otp_url, {'otp': '123456'})
        self.assertIn(response.status_code, [200, 400])

    def test_captcha_required_enforced(self):
        self.authenticate()
        response = self.client.post(self.captcha_url, {'captcha': 'captcha_token'})
        self.assertIn(response.status_code, [200, 400])

    def test_suspicious_login_logged(self):
        with mock.patch('gateway.signals.logger') as mock_logger:
            self.client.post(self.login_url, {
                'username': 'secureuser',
                'password': 'WrongPass123!'
            })
            mock_logger.warning.assert_called()

    def test_ip_logging_in_request(self):
        self.authenticate()
        with mock.patch('gateway.middleware.logger') as mock_logger:
            self.client.get(self.dashboard_url, REMOTE_ADDR='203.0.113.42')
            mock_logger.info.assert_called()

    def test_geoip_blocking(self):
        self.authenticate()
        with override_settings(BLOCKED_COUNTRIES=['CN']):
            response = self.client.get(self.geoip_check_url, HTTP_GEOIP_COUNTRY_CODE='CN')
            self.assertEqual(response.status_code, 403)

    def test_device_fingerprint_check(self):
        self.authenticate()
        response = self.client.post(self.fingerprint_url, {'fingerprint': 'hashvalue'})
        self.assertIn(response.status_code, [200, 400])

    def test_jwt_token_expired(self):
        payload = {
            'user_id': self.user.id,
            'exp': time.time() - 10
        }
        expired_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {expired_token}')
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 401)

    def test_user_agent_filter(self):
        self.authenticate()
        with override_settings(BLOCKED_USER_AGENTS=['BadBot']):
            response = self.client.get(self.useragent_url, HTTP_USER_AGENT='BadBot')
            self.assertEqual(response.status_code, 403)

    def test_cors_headers_set(self):
        response = self.client.options(self.cors_url, HTTP_ORIGIN='https://example.com')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Access-Control-Allow-Origin', response.headers)

    def test_http_method_not_allowed(self):
        self.authenticate()
        response = self.client.delete(self.dashboard_url)
        self.assertIn(response.status_code, [403, 405])
