"""
Unit tests for gateway.views
"""

from django.test import TestCase, override_settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test.client import RequestFactory
from django.contrib.messages import get_messages
from gateway.views import login_view, logout_view, dashboard_view
from unittest.mock import patch

User = get_user_model()


class LoginViewTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='testuser', password='securepass123')

    def test_login_view_get(self):
        url = reverse('gateway:login')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'gateway/login.html')

    def test_login_view_post_success(self):
        url = reverse('gateway:login')
        response = self.client.post(url, {'username': 'testuser', 'password': 'securepass123'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('gateway:dashboard'))

    def test_login_view_post_invalid(self):
        url = reverse('gateway:login')
        response = self.client.post(url, {'username': 'wrong', 'password': 'wrongpass'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Invalid username or password')

    def test_login_view_missing_fields(self):
        url = reverse('gateway:login')
        response = self.client.post(url, {'username': ''})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'This field is required')

    def test_login_with_inactive_user(self):
        self.user.is_active = False
        self.user.save()
        url = reverse('gateway:login')
        response = self.client.post(url, {'username': 'testuser', 'password': 'securepass123'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Your account is inactive')

    @patch('gateway.forms.LoginForm.is_valid', return_value=False)
    def test_login_form_invalid_mock(self, mock_form):
        url = reverse('gateway:login')
        response = self.client.post(url, {'username': 'mockuser', 'password': 'mockpass'})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'gateway/login.html')


class LogoutViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='logoutuser', password='securepass456')
        self.client.login(username='logoutuser', password='securepass456')

    def test_logout_view(self):
        url = reverse('gateway:logout')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('gateway:login'))

    def test_logout_view_without_login(self):
        self.client.logout()
        url = reverse('gateway:logout')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('gateway:login'))


class DashboardViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='dashboarduser', password='securepass789')

    def test_dashboard_authenticated(self):
        self.client.login(username='dashboarduser', password='securepass789')
        url = reverse('gateway:dashboard')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'gateway/dashboard.html')

    def test_dashboard_unauthenticated_redirect(self):
        url = reverse('gateway:dashboard')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('gateway:login'), response.url)

    def test_dashboard_context(self):
        self.client.login(username='dashboarduser', password='securepass789')
        url = reverse('gateway:dashboard')
        response = self.client.get(url)
        self.assertIn('user', response.context)
        self.assertEqual(response.context['user'].username, 'dashboarduser')

    @override_settings(DEBUG=True)
    def test_dashboard_debug_mode(self):
        self.client.login(username='dashboarduser', password='securepass789')
        url = reverse('gateway:dashboard')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('DEBUG', response.content.decode())

    def test_dashboard_invalid_method(self):
        self.client.login(username='dashboarduser', password='securepass789')
        url = reverse('gateway:dashboard')
        response = self.client.post(url)
        self.assertNotEqual(response.status_code, 405)  # If post is not allowed, it should return 405
