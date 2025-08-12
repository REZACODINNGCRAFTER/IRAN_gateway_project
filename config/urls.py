"""
URL configuration for the Django project.
Routes requests to appropriate apps, integrates API docs,
custom error pages, health checks, and optionally multilingual URLs.
Also supports API versioning and optional diagnostics endpoints.
"""

from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import TemplateView
from django.utils.translation import gettext_lazy as _

# Optional: API schema and docs
# from rest_framework.schemas import get_schema_view
# from rest_framework.documentation import include_docs_urls
# from drf_yasg.views import get_schema_view as get_yasg_schema_view
# from drf_yasg import openapi

# Optional: i18n language support
from django.conf.urls.i18n import i18n_patterns

# Optional: diagnostics or heartbeat views
from gateway.views import heartbeat_view

# Base urlpatterns (non-translatable)
urlpatterns = [
    path("healthz/", TemplateView.as_view(template_name="health_check.html"), name="health_check"),
    path("heartbeat/", heartbeat_view, name="heartbeat"),
    path("api/v1/", include('api_gateway.urls', namespace='apiv1')),
    # Optionally add versioned API v2 endpoints below
    # path("api/v2/", include('api_v2.urls', namespace='apiv2')),
]

# i18n-aware routes
urlpatterns += i18n_patterns(
    path(_('admin/'), admin.site.urls),
    path(_('gateway/'), include('gateway.urls')),
    path(_('accounts/'), include('accounts.urls')),

    # Optional documentation endpoints
    # path(_('docs/'), include_docs_urls(title=_('API Documentation'))),
    # path(_('openapi/'), get_schema_view(...), name='openapi-schema'),
    # path(_('swagger/'), get_yasg_schema_view(
    #     openapi.Info(
    #         title="API",
    #         default_version='v1',
    #         description="API Documentation",
    #     ),
    #     public=True
    # ).with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
)

# Serve media/static files in development only
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Custom error handlers
handler400 = 'gateway.views.error_400'
handler403 = 'gateway.views.error_403'
handler404 = 'gateway.views.error_404'
handler500 = 'gateway.views.error_500'
