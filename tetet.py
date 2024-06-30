from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import *
from .serializers import *
from .permissions import IsOwnerOrReadOnly
from django.core.mail import send_mail
from django.conf import settings
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from rest_framework.decorators import action
from rest_framework import viewsets

class UserRegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            try:
                role = Role.objects.get(name='user')
                user.role = role
                user.save()
                try:
                    send_mail(
                        'Your OTP Code',
                        f'Your OTP code is {user.otp_code}',
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                    )
                    return Response({"message": "User created. Check your email for the OTP code."}, status=status.HTTP_201_CREATED)
                except Exception as e:
                    return Response({"message": f"User created but failed to send OTP email: {str(e)}"}, status=status.HTTP_201_CREATED)
            except Role.DoesNotExist:
                return Response({"error": "Role 'user' does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            errors = serializer.errors
            conflict_fields = [
                {"field": field, "error": error[0]} for field, error in errors.items() if error[0].code == 'unique'
            ]
            field_requies = [
                {"field": field, "error": error[0]} for field, error in errors.items() if error[0].code == 'required'
            ]
            other_errors = [
                {"field": field, "error": error[0]} for field, error in errors.items() if error[0].code != 'unique'
            ]

            if conflict_fields:
                return Response(
                    {
                        "message": "Your account already exists. Failed to create a new account.",
                        "status": 409,
                        "errors": conflict_fields
                    },
                    status=status.HTTP_409_CONFLICT
                )

            return Response(
                {
                    "message": "Validation errors occurred.",
                    "status": 400,
                    "errors": field_requies
                },
                status=status.HTTP_400_BAD_REQUEST
            )

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Check if email and password are provided
        if not email or not password:
            missing_fields = []
            if not email:
                missing_fields.append("email")
            if not password:
                missing_fields.append("password")
            return Response(
                {
                    "message": "Email and password are required.",
                    "missing_fields": missing_fields
                }, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return Response({"message": "Invalid email format."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if user with provided email exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)

        # Authenticate user
        user = authenticate(request, username=user.username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response({"message": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)

class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = User.objects.get(email=serializer.validated_data['email'])
                if user.verify_otp(serializer.validated_data['otp_code']):
                    return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
                return Response({"error": "Invalid OTP code."}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({"error": "Invalid email or OTP code."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                if user.is_verified:
                    return Response({"message": "Email is already verified."}, status=status.HTTP_400_BAD_REQUEST)
                
                user.set_otp()
                send_mail(
                    'Your OTP Code',
                    f'Your new OTP code is {user.otp_code}',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                )
                return Response({"message": "New OTP sent to your email."}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"message": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data)

    def put(self, request):
        user = request.user
        serializer = UserProfileSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Profile updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateUserRoleView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        serializer = UpdateUserRoleSerializer(data=request.data)
        if serializer.is_valid():
            user = User.objects.get(id=serializer.validated_data['user_id'])
            role = Role.objects.get(id=serializer.validated_data['role_id'])

            user.role = role
            user.save()

            return Response({"message": "User role updated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_permissions(self):
        if self.action == 'list':
            self.permission_classes = [IsAuthenticated, IsAdminUser]
        elif self.action in ['retrieve', 'update', 'partial_update', 'destroy']:
            if self.action == 'update' or self.action == 'partial_update':
                if self.request.user.role.name != 'admin' and self.request.user != self.get_object():
                    self.permission_classes = [IsAuthenticated, IsAdminUser]
                else:
                    self.permission_classes = [IsAuthenticated]
            else:
                self.permission_classes = [IsAuthenticated]
        return super(UserViewSet, self).get_permissions()

class TemplatePortfolioListCreateView(generics.ListCreateAPIView):
    queryset = TemplatePortfolio.objects.all()
    serializer_class = TemplatePortfolioSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            errors = serializer.errors
            formatted_errors = [{"field": field, "error": error[0]} for field, error in errors.items()]
            return Response(
                {
                    "message": "Validation errors occurred.",
                    "status": 400,
                    "errors": formatted_errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer.save(created_by=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class TemplatePortfolioDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = TemplatePortfolio.objects.all()
    serializer_class = TemplatePortfolioSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if not serializer.is_valid():
            errors = serializer.errors
            formatted_errors = [{"field": field, "error": error[0]} for field, error in errors.items()]
            return Response(
                {
                    "message": "Validation errors occurred.",
                    "status": 400,
                    "errors": formatted_errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

class SelectTemplateListCreateView(generics.ListCreateAPIView):
    queryset = SelectTemplate.objects.all()
    serializer_class = SelectTemplateSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            errors = serializer.errors
            if any(field in errors for field in ["user", "template"]):
                formatted_errors = [{"field": field, "error": error[0]} for field, error in errors.items()]
                return Response(
                    {
                        "message": "Validation errors occurred.",
                        "status": 400,
                        "errors": formatted_errors
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class SelectTemplateDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = SelectTemplate.objects.all()
    serializer_class = SelectTemplateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if not serializer.is_valid():
            errors = serializer.errors
            if any(field in errors for field in ["user", "template"]):
                formatted_errors = [{"field": field, "error": error[0]} for field, error in errors.items()]
                return Response(
                    {
                        "message": "Validation errors occurred.",
                        "status": 400,
                        "errors": formatted_errors
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

class UploadPortfolioListCreateView(generics.ListCreateAPIView):
    queryset = UploadPortfolio.objects.all()
    serializer_class = UploadPortfolioSerializer
    permission_classes = [permissions.AllowAny]

class DraftPortfolioListCreateView(generics.ListCreateAPIView):
    queryset = DraftPortfolio.objects.all()
    serializer_class = DraftPortfolioSerializer
    permission_classes = [permissions.AllowAny]
"url": "http://127.0.0.1:8000/username/name ot template/autoategetnt/"
