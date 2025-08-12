"""
REST Framework configuration component for Django project.
This module should be imported in settings/base.py or settings/api.py.
"""

from datetime import timedelta
import os

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ),
    'DEFAULT_PARSER_CLASSES': (
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ),
    'DEFAULT_THROTTLE_CLASSES': (
        'rest_framework.throttling.UserRateThrottle',
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.ScopedRateThrottle',
    ),
    'DEFAULT_THROTTLE_RATES': {
        'user': os.getenv('DRF_USER_THROTTLE_RATE', '1000/day'),
        'anon': os.getenv('DRF_ANON_THROTTLE_RATE', '100/day'),
        'login': os.getenv('DRF_LOGIN_THROTTLE_RATE', '10/minute'),
        'signup': os.getenv('DRF_SIGNUP_THROTTLE_RATE', '5/hour'),
    },
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': int(os.getenv('DRF_PAGE_SIZE', 10)),
    'EXCEPTION_HANDLER': 'rest_framework.views.exception_handler',
    'DEFAULT_SCHEMA_CLASS': 'rest_framework.schemas.openapi.AutoSchema',
    'DEFAULT_FILTER_BACKENDS': (
        'rest_framework.filters.OrderingFilter',
        'rest_framework.filters.SearchFilter',
        'django_filters.rest_framework.DjangoFilterBackend',
    ),
    'UNAUTHENTICATED_USER': None,
    'DATETIME_FORMAT': "%Y-%m-%d %H:%M:%S",
    'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.NamespaceVersioning',
    'DEFAULT_METADATA_CLASS': 'rest_framework.metadata.SimpleMetadata',
    'DEFAULT_CONTENT_NEGOTIATION_CLASS': 'rest_framework.negotiation.DefaultContentNegotiation',
    'DEFAULT_RENDERER_CLASSES_DEBUG': (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ),
    'DEFAULT_AUTHENTICATION_HEADER': 'Bearer',
    'STRICT_JSON': os.getenv('DRF_STRICT_JSON', 'False') == 'True',
    'ENABLE_HTML_RENDERING': os.getenv('DRF_ENABLE_HTML_RENDERING', 'False') == 'True',
    'DEFAULT_CACHE_RESPONSE_TIMEOUT': int(os.getenv('DRF_CACHE_TIMEOUT', 60)),
    'DEFAULT_VERSION': 'v1',
    'ALLOWED_VERSIONS': ['v1', 'v2'],
    'DEFAULT_CONTENT_TYPE': 'application/json',
}

# JWT Configuration for SimpleJWT
token_lifetime_minutes = int(os.getenv("JWT_ACCESS_TOKEN_LIFETIME", 5))
refresh_lifetime_days = int(os.getenv("JWT_REFRESH_TOKEN_LIFETIME", 1))

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=token_lifetime_minutes),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=refresh_lifetime_days),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': os.getenv("SECRET_KEY"),
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',

    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',

    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=token_lifetime_minutes),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=refresh_lifetime_days),

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',

    'LEEWAY': 30,
    'JTI_CLAIM': 'jti',
    'TOKEN_OBTAIN_SERIALIZER': 'rest_framework_simplejwt.serializers.TokenObtainPairSerializer',
    'TOKEN_REFRESH_SERIALIZER': 'rest_framework_simplejwt.serializers.TokenRefreshSerializer',
    'TOKEN_VERIFY_SERIALIZER': 'rest_framework_simplejwt.serializers.TokenVerifySerializer',
    'TOKEN_BLACKLIST_SERIALIZER': 'rest_framework_simplejwt.serializers.TokenBlacklistSerializer',
    'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',
    'SIGNING_KEY_ROTATION_ENABLED': os.getenv("JWT_KEY_ROTATION", "False") == "True",
    'ISSUER': os.getenv("JWT_ISSUER", "gateway.api"),
}
