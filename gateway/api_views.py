from rest_framework import status, permissions, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, OutstandingToken, BlacklistedToken
from django.contrib.auth import authenticate, get_user_model
from django.utils.timezone import now
from gateway.serializers import (
    LoginRequestSerializer,
    RegistrationSerializer,
    TokenRefreshSerializer,
    ProfileUpdateSerializer,
    DeactivateAccountSerializer,
    FeedbackSerializer,
    TwoFactorAuthSetupSerializer,
    EmailVerificationSerializer,
    DeviceRegistrationSerializer,
    CAPTCHAValidationSerializer,
    SessionLogSerializer,
    IPReputationCheckSerializer
)
from gateway.models import SessionLog

User = get_user_model()


class LoginAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(
            request,
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password']
        )
        if user is not None:
            refresh = RefreshToken.for_user(user)
            SessionLog.objects.create(user=user, ip_address=request.META.get('REMOTE_ADDR'), login_time=now())
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            })
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class RegisterAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.create_user(
            username=serializer.validated_data['username'],
            email=serializer.validated_data['email'],
            password=serializer.validated_data['password']
        )
        return Response({'detail': 'User registered successfully'}, status=status.HTTP_201_CREATED)


class TokenRefreshAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = TokenRefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh = RefreshToken(serializer.validated_data['refresh'])
            return Response({
                'access': str(refresh.access_token)
            })
        except Exception:
            return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LogoutAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'detail': 'Logged out successfully'}, status=status.HTTP_200_OK)
        except Exception:
            return Response({'detail': 'Logout failed'}, status=status.HTTP_400_BAD_REQUEST)


class ProfileUpdateAPIView(generics.UpdateAPIView):
    serializer_class = ProfileUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


class DeactivateAccountAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = DeactivateAccountSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer.validated_data['confirm']:
            user = request.user
            if not user.check_password(serializer.validated_data['password']):
                return Response({'detail': 'Incorrect password'}, status=status.HTTP_400_BAD_REQUEST)
            user.is_active = False
            user.save()
            return Response({'detail': 'Account deactivated'}, status=status.HTTP_200_OK)
        return Response({'detail': 'Confirmation required'}, status=status.HTTP_400_BAD_REQUEST)


class FeedbackAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = FeedbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'detail': 'Feedback submitted'}, status=status.HTTP_200_OK)


class TwoFactorSetupAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = TwoFactorAuthSetupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'detail': '2FA setup instructions sent'}, status=status.HTTP_200_OK)


class EmailVerificationAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'detail': 'Email verified'}, status=status.HTTP_200_OK)


class DeviceRegistrationAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = DeviceRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'detail': 'Device registered'}, status=status.HTTP_200_OK)


class CAPTCHAValidationAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = CAPTCHAValidationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'detail': 'CAPTCHA verified'}, status=status.HTTP_200_OK)


class SessionLogListAPIView(generics.ListAPIView):
    serializer_class = SessionLogSerializer
    permission_classes = [permissions.IsAdminUser]

    def get_queryset(self):
        return SessionLog.objects.all().order_by('-timestamp')


class IPReputationAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = IPReputationCheckSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ip = serializer.validated_data['ip_address']
        reputation_score = 85 if ip.startswith('192.') else 45
        return Response({'ip': ip, 'reputation_score': reputation_score}, status=status.HTTP_200_OK)


class BlacklistedTokensAPIView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        tokens = BlacklistedToken.objects.select_related('token').all()
        token_data = [{'token': str(token.token.token), 'user_id': token.token.user_id} for token in tokens]
        return Response({'blacklisted_tokens': token_data}, status=status.HTTP_200_OK)


class ImpersonateUserAPIView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def post(self, request):
        target_user_id = request.data.get('user_id')
        try:
            target_user = User.objects.get(id=target_user_id)
            refresh = RefreshToken.for_user(target_user)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            })
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class ActiveSessionsAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user_sessions = SessionLog.objects.filter(user=request.user).order_by('-login_time')[:10]
        data = SessionLogSerializer(user_sessions, many=True).data
        return Response({'active_sessions': data}, status=status.HTTP_200_OK)


class RevokeAllTokensAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        tokens = OutstandingToken.objects.filter(user=request.user)
        for token in tokens:
            try:
                BlacklistedToken.objects.get_or_create(token=token)
            except Exception:
                continue
        return Response({'detail': 'All tokens revoked'}, status=status.HTTP_200_OK)
