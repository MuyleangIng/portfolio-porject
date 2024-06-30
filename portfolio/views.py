from rest_framework import generics, permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import *
from .serializers import *
from .permissions import IsOwnerOrReadOnly
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny,IsAuthenticatedOrReadOnly
from django.shortcuts import get_object_or_404

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

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response({"message": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    # @swagger_auto_schema(request_body=OTPSerializer, responses={200: 'Email verified successfully.'})
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

    # @swagger_auto_schema(responses={200: UserProfileSerializer})
    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data)

    # @swagger_auto_schema(request_body=UserProfileSerializer, responses={200: UserProfileSerializer})
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
            # Only admin users can list all users
            self.permission_classes = [IsAuthenticated, IsAdminUser]
        elif self.action in ['retrieve', 'update', 'partial_update', 'destroy']:
            # Only the user themselves or an admin can retrieve, update, or delete a user profile
            self.permission_classes = [IsAuthenticated]
        return super(UserViewSet, self).get_permissions()


class RoleListCreateView(generics.ListCreateAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated]


class ContactListCreateView(generics.ListCreateAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    permission_classes = [permissions.IsAuthenticated]

class ContactDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    permission_classes = [permissions.IsAuthenticated]

class BlogListCreateView(generics.ListCreateAPIView):
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer
    permission_classes = [permissions.IsAuthenticated]

class BlogDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer
    permission_classes = [permissions.IsAuthenticated]

class SkillListCreateView(generics.ListCreateAPIView):
    queryset = Skill.objects.all()
    serializer_class = SkillSerializer
    permission_classes = [permissions.IsAuthenticated]

class SkillDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Skill.objects.all()
    serializer_class = SkillSerializer
    permission_classes = [permissions.IsAuthenticated]

class WorkExperienceListCreateView(generics.ListCreateAPIView):
    queryset = WorkExperience.objects.all()
    serializer_class = WorkExperienceSerializer
    permission_classes = [permissions.IsAuthenticated]

class WorkExperienceDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = WorkExperience.objects.all()
    serializer_class = WorkExperienceSerializer
    permission_classes = [permissions.IsAuthenticated]

class ServiceListCreateView(generics.ListCreateAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [permissions.IsAuthenticated]

class ServiceDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [permissions.IsAuthenticated]

class ProjectListCreateView(generics.ListCreateAPIView):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer
    permission_classes = [permissions.IsAuthenticated]

class ProjectDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer
    permission_classes = [permissions.IsAuthenticated]
# Define TemplateListCreateView
class TemplateListCreateView(generics.ListCreateAPIView):
    queryset = Template.objects.all()
    serializer_class = TemplateSerializer
    permission_classes = [permissions.AllowAny]

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
class TemplatePortfolioListCreateView(generics.ListCreateAPIView):
    queryset = TemplatePortfolio.objects.all()
    serializer_class = TemplatePortfolioSerializer
    permission_classes = [permissions.AllowAny]

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
    serializer_class = TemplatePortfolioSerializer
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
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
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
    permission_classes = [permissions.IsAuthenticated]

class UploadPortfolioDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = UploadPortfolio.objects.all()
    serializer_class = UploadPortfolioSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

class DraftPortfolioListCreateView(generics.ListCreateAPIView):
    queryset = DraftPortfolio.objects.all()
    serializer_class = DraftPortfolioSerializer
    permission_classes = [permissions.IsAuthenticated]

class DraftPortfolioDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = DraftPortfolio.objects.all()
    serializer_class = DraftPortfolioSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
