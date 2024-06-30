from rest_framework import serializers
from .models import *
class UserSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'username']

class UserRegistrationSerializer(serializers.ModelSerializer):
    confirmPassword = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'confirmPassword')
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        errors = {}
        if data['password'] != data['confirmPassword']:
            errors['password'] = "Passwords do not match."

        existing_user_by_email = User.objects.filter(email=data['email']).first()
        existing_user_by_username = User.objects.filter(username=data['username']).first()

        if existing_user_by_email:
            if not existing_user_by_email.is_active:
                errors['message'] = "Your account has been created. Please check and verify your email address."
            else:
                errors['email'] = "User with this email already exists."
        if existing_user_by_username:
            if not existing_user_by_username.is_active:
                errors['message'] = "Your account has been created. Please check and verify your email address."
            else:
                errors['username'] = "User with this username already exists."

        if errors:
            raise serializers.ValidationError(errors)
        return data

    def create(self, validated_data):
        validated_data.pop('confirmPassword')
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password']
        )
        user.set_otp()
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    role = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'gender', 'dob', 'username', 
            'email', 'phone_number', 'bio', 'avatar', 'address', 
            'facebook', 'twitter', 'instagram', 'linkedin', 'role'
        ]
        extra_kwargs = {
            'email': {'read_only': True}  # Prevent email from being updated
        }

    def validate_username(self, value):
        if not value.isalnum():
            raise serializers.ValidationError("Username should only contain alphanumeric characters.")
        return value
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email')

class OTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6)

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'

class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = '__all__'

class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = '__all__'

class BlogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blog
        fields = '__all__'

class SkillSerializer(serializers.ModelSerializer):
    class Meta:
        model = Skill
        fields = '__all__'

class WorkExperienceSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkExperience
        fields = '__all__'

class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = '__all__'

class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = '__all__'

class TemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Template
        fields = '__all__'
class TemplatePortfolioPublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = TemplatePortfolio
        fields = ['is_public']
class TemplatePortfolioSerializer(serializers.ModelSerializer):
    created_by = serializers.SerializerMethodField()
    url = serializers.SerializerMethodField()

    class Meta:
        model = TemplatePortfolio
        fields = [
            'id', 'title', 'type', 'social_media_link_json', 'portfolio_avatar', 
            'biography', 'we', 'project', 'status', 'hero_image', 'created_at', 
            'updated_at', 'section_image', 'contact', 'blog', 'service', 'skill', 
            'template', 'created_by', 'select_template', 'is_public', 'unique_slug', 'url'
        ]

    def get_created_by(self, obj):
        return obj.created_by.username

    def get_url(self, obj):
        request = self.context.get('request')
        if obj.is_public:
            return request.build_absolute_uri(reverse('public-portfolio-view', args=[obj.created_by.username, obj.unique_slug]))
        return None

    def create(self, validated_data):
        request = self.context.get('request', None)
        if request:
            validated_data['created_by'] = request.user
        return super().create(validated_data)
class SelectTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SelectTemplate
        fields = '__all__'

    def validate(self, data):
        errors = {}
        user = data.get('user')
        template = data.get('template')

        if not user:
            errors['user'] = "User is required."
        if not template:
            errors['template'] = "Template is required."

        if errors:
            raise serializers.ValidationError(errors)
        
        return data

class UploadPortfolioSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadPortfolio
        fields = '__all__'

class DraftPortfolioSerializer(serializers.ModelSerializer):
    class Meta:
        model = DraftPortfolio
        fields = '__all__'
