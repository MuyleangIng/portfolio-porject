from rest_framework import generics, permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import *
from .serializers import *
from .permissions import IsOwner
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from django.shortcuts import get_object_or_404
from http import HTTPStatus
from .custom_views import CustomListCreateAPIView
from rest_framework.parsers import MultiPartParser, FormParser
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
class ResendRegistrationOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            if not user.is_verified:
                user.set_otp()
                send_mail(
                    'Your New OTP Code',
                    f'Your new OTP code is {user.otp_code}',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                )
                return Response({"message": "New OTP code sent to your email address."}, status=status.HTTP_200_OK)
            return Response({"message": "Email is already verified. No need to resend OTP."}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)
class PasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Password reset successfully. You can now log in with the new password."
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            user.set_otp()
            send_mail(
                'Your OTP Code for Password Reset',
                f'Your OTP code is {user.otp_code}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
            )
            return Response({
                "message": "OTP code sent to your email address."
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
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
            print(errors)
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
        user = authenticate(request, email=email, password=password)
        if not email or not password:

            missing_fields = []
            print('this is missing_fields',missing_fields)
            if not email:
                missing_fields.append("email")
            if not password:
                missing_fields.append("password")
            return Response(
                {
                    "message": "Email and password are required.",
                    "status": 400,
                }, 
                status=status.HTTP_400_BAD_REQUEST
            )
        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                "status": HTTPStatus.OK
            })
        return Response({
            "message": "Invalid email or password",
            "status": 401,
            }, status=status.HTTP_401_UNAUTHORIZED)

# class LoginView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         email = request.data.get('email')
#         password = request.data.get('password')
#         user = authenticate(request, email=email, password=password)

#         if user is not None:
#             refresh = RefreshToken.for_user(user)
#             return Response({
#                 'refresh': str(refresh),
#                 'access': str(refresh.access_token),
#             })
#         return Response({"message": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = User.objects.get(email=serializer.validated_data['email'])
                if user.verify_otp(serializer.validated_data['otp_code']):
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'message': 'Email verified successfully.',
                    }, status=status.HTTP_200_OK)
                return Response({"error": "Invalid OTP code."}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({"error": "Invalid email or OTP code."}, status=status.HTTP_400_BAD_REQUEST)
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

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer

    def get_permissions(self):
        if self.action == 'list':
            self.permission_classes = [IsAuthenticated, IsAdminUser]
        elif self.action in ['retrieve', 'update', 'partial_update', 'destroy']:
            self.permission_classes = [IsOwner]
        return super(UserViewSet, self).get_permissions()

    def get_queryset(self):
        if self.request.user.is_staff:
            return User.objects.all()
        return User.objects.filter(id=self.request.user.id)

class RoleListCreateView(CustomListCreateAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated]
class ContactListCreateView(CustomListCreateAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get_queryset(self):
        if self.request.user.is_staff:
            return Contact.objects.all()
        return Contact.objects.filter(created_by=self.request.user)
    def get_serializer_context(self):
        return {'request': self.request}
        

class ContactDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    permission_classes = [IsAuthenticated]

class BlogListCreateView(CustomListCreateAPIView):
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        if self.request.user.is_staff:
            return Blog.objects.all()
        return Blog.objects.filter(created_by=self.request.user)

    def get_serializer_context(self):
        return {'request': self.request}

class BlogDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

class SkillListCreateView(CustomListCreateAPIView):
    queryset = Skill.objects.all()
    serializer_class = SkillSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get_queryset(self):
        if self.request.user.is_staff:
            return Skill.objects.all()
        return Skill.objects.filter(created_by=self.request.user)
    def get_serializer_context(self):
        return {'request': self.request}

class SkillDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Skill.objects.all()
    serializer_class = SkillSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

class WorkExperienceListCreateView(CustomListCreateAPIView):
    queryset = WorkExperience.objects.all()
    serializer_class = WorkExperienceSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get_queryset(self):
        if self.request.user.is_staff:
            return WorkExperience.objects.all()
        return WorkExperience.objects.filter(created_by=self.request.user)
    def get_serializer_context(self):
        return {'request': self.request}

class WorkExperienceDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = WorkExperience.objects.all()
    serializer_class = WorkExperienceSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

# class ServiceListCreateView(CustomListCreateAPIView):
#     queryset = Service.objects.all()
#     serializer_class = ServiceSerializer
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         if self.request.user.is_staff:
#             return Service.objects.all()
#         return Service.objects.filter(created_by=self.request.user)
class ServiceListCreateView(CustomListCreateAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        if self.request.user.is_staff:
            return Service.objects.all()
        return Service.objects.filter(created_by=self.request.user)
    def get_queryset(self):
        if self.request.user.is_staff:
            return Service.objects.all()
        return Service.objects.filter(created_by=self.request.user)
class ServiceDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsOwner]
    def get(self, request, *args, **kwargs):
        instance = self.get_object()
        if not instance.is_public and instance.created_by != request.user:
            return Response(
                {"message": "You do not have permission to view this portfolio."},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer = self.get_serializer(instance)
        return Response(serializer.data)    

class ProjectListCreateView(CustomListCreateAPIView):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        if self.request.user.is_staff:
            return Project.objects.all()
        return Project.objects.filter(created_by=self.request.user)
    def get_queryset(self):
        if self.request.user.is_staff:
            return Project.objects.all()
        return Project.objects.filter(created_by=self.request.user)

class ProjectDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

class TemplateListCreateView(CustomListCreateAPIView):
    queryset = Template.objects.all()
    serializer_class = TemplateSerializer
    permission_classes = [AllowAny]

class TemplatePortfolioDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = TemplatePortfolio.objects.all()
    serializer_class = TemplatePortfolioSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def get(self, request, *args, **kwargs):
        instance = self.get_object()
        if not instance.is_public and instance.created_by != request.user:
            return Response(
                {"message": "You do not have permission to view this portfolio."},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

class TemplatePortfolioListCreateView(CustomListCreateAPIView):
    queryset = TemplatePortfolio.objects.all()
    serializer_class = TemplatePortfolioSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if self.request.user.is_staff:
            return TemplatePortfolio.objects.all()
        return TemplatePortfolio.objects.filter(created_by=self.request.user)

    def get_serializer_context(self):
        return {'request': self.request}

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
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class PublicPortfolioView(generics.RetrieveAPIView):
    queryset = TemplatePortfolio.objects.all()
    serializer_class = CustomTemplatePortfolioSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request, username, unique_slug, *args, **kwargs):
        portfolio = get_object_or_404(TemplatePortfolio, created_by__username=username, unique_slug=unique_slug)
        if not portfolio.is_public:
            return Response(
                {"message": "This portfolio is not public."},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer = self.get_serializer(portfolio)
        return Response(serializer.data)

class TemplatePortfolioPublicUpdateView(generics.UpdateAPIView):
    queryset = TemplatePortfolio.objects.all()
    serializer_class = TemplatePortfolioPublicSerializer
    permission_classes = [IsOwner]

    def patch(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SelectTemplateListCreateView(CustomListCreateAPIView):
    queryset = SelectTemplate.objects.all()
    serializer_class = SelectTemplateSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if self.request.user.is_staff:
            return SelectTemplate.objects.all()
        return SelectTemplate.objects.filter(user=self.request.user)

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
    permission_classes = [IsOwner]

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

class UploadPortfolioListCreateView(CustomListCreateAPIView):
    queryset = UploadPortfolio.objects.all()
    serializer_class = UploadPortfolioSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if self.request.user.is_staff:
            return UploadPortfolio.objects.all()
        return UploadPortfolio.objects.filter(created_by=self.request.user)

class UploadPortfolioDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = UploadPortfolio.objects.all()
    serializer_class = UploadPortfolioSerializer
    permission_classes = [IsOwner]

class DraftPortfolioListCreateView(CustomListCreateAPIView):
    queryset = DraftPortfolio.objects.all()
    serializer_class = DraftPortfolioSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if self.request.user.is_staff:
            return DraftPortfolio.objects.all()
        return DraftPortfolio.objects.filter(created_by=self.request.user)

class DraftPortfolioDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = DraftPortfolio.objects.all()
    serializer_class = DraftPortfolioSerializer
    permission_classes = [IsOwner]
class UploadedFileView(generics.ListCreateAPIView):
    queryset = UploadedFile.objects.all()
    serializer_class = UploadedFileSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [AllowAny]

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)