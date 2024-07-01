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
        fields = ['id', 'address', 'contact_email', 'phone', 'title', 'description', 'created_by']
        extra_kwargs = {'created_by': {'read_only': True}}

    def create(self, validated_data):
        request = self.context.get('request', None)
        if request and request.user.is_authenticated:
            validated_data['created_by'] = request.user
        return super().create(validated_data)

# class BlogSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Blog
#         fields = ['id', 'image', 'title', 'description', 'created_at', 'updated_at', 'created_by']
#         extra_kwargs = {'created_by': {'read_only': True}}

#     def create(self, validated_data):
#         request = self.context.get('request', None)
#         if request and request.user.is_authenticated:
#             validated_data['created_by'] = request.user
#         return super().create(validated_data)
class BlogSerializer(serializers.ModelSerializer):
    images = serializers.ListField(
        child=serializers.CharField(),
        source='image',
        write_only=True
    )
    image = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Blog
        fields = ['id', 'title', 'description', 'images', 'image', 'created_at', 'updated_at', 'created_by']
        extra_kwargs = {'created_by': {'read_only': True}}

    def get_image(self, obj):
        return [{'url': img, 'alt': f'Image {i+1}'} for i, img in enumerate(obj.image)]

    def create(self, validated_data):
        images = validated_data.pop('image', [])
        request = self.context.get('request', None)
        if request and request.user.is_authenticated:
            validated_data['created_by'] = request.user
        validated_data['image'] = images
        return super().create(validated_data)
class SkillSerializer(serializers.ModelSerializer):
    images = serializers.ListField(
        child=serializers.CharField(),
        source='image',
        write_only=True
    )
    image = serializers.SerializerMethodField(read_only=True)    
    class Meta:
        model = Skill
        fields = ['id', 'title','images', 'image', 'description', 'updated_at', 'created_by']
        extra_kwargs = {'created_by': {'read_only': True}}

    def get_image(self, obj):
        return [{'url': img, 'alt': f'Image {i+1}'} for i, img in enumerate(obj.image)]

    def create(self, validated_data):
        images = validated_data.pop('image', [])
        request = self.context.get('request', None)
        if request and request.user.is_authenticated:
            validated_data['created_by'] = request.user
        validated_data['image'] = images
        return super().create(validated_data)

class WorkExperienceSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkExperience
        fields = ['id', 'job_title', 'hired_date', 'achievements', 'job_description', 'position', 'responsibility', 'work_address', 'company_name', 'created_by']
        extra_kwargs = {'created_by': {'read_only': True}}

    def create(self, validated_data):
        request = self.context.get('request', None)
        if request and request.user.is_authenticated:
            validated_data['created_by'] = request.user
        return super().create(validated_data)

class ServiceSerializer(serializers.ModelSerializer):
    images = serializers.ListField(
        child=serializers.CharField(),
        source='image',
        write_only=True
    )
    image = serializers.SerializerMethodField(read_only=True)    
    class Meta:
        model = Service
        fields = ['id', 'image','images', 'title', 'description', 'created_at', 'updated_at', 'created_by']
        extra_kwargs = {'created_by': {'read_only': True}}
    def get_image(self, obj):
        return [{'url': img, 'alt': f'Image {i+1}'} for i, img in enumerate(obj.image)]
    def create(self, validated_data):
        images = validated_data.pop('image', [])
        request = self.context.get('request', None)
        if request and request.user.is_authenticated:
            validated_data['created_by'] = request.user
        validated_data['image'] = images
        return super().create(validated_data)
class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ['id', 'project_title', 'project_description', 'link_to_project', 'project_image', 'created_at', 'updated_at', 'created_by']
        extra_kwargs = {'created_by': {'read_only': True}}

    def create(self, validated_data):
        request = self.context.get('request', None)
        if request and request.user.is_authenticated:
            validated_data['created_by'] = request.user
        return super().create(validated_data)

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
class CustomTemplatePortfolioSerializer(serializers.ModelSerializer):
    created_by = serializers.SerializerMethodField()
    url = serializers.SerializerMethodField()
    we = WorkExperienceSerializer()
    project = ProjectSerializer()
    skill = SkillSerializer()
    service = ServiceSerializer()
    blog = BlogSerializer()
    contact = ContactSerializer()
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
    def get_we(self, obj):
        return WorkExperienceSerializer(obj.we).data if obj.we else None

    def get_project(self, obj):
        return ProjectSerializer(obj.project).data if obj.project else None

    def get_contact(self, obj):
        return ContactSerializer(obj.contact).data if obj.contact else None

    def get_blog(self, obj):
        return BlogSerializer(obj.blog).data if obj.blog else None

    def get_service(self, obj):
        return ServiceSerializer(obj.service).data if obj.service else None

    def get_skill(self, obj):
        return SkillSerializer(obj.skill).data if obj.skill else None

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        # Remove `id` and `created_by` from nested representations
        for nested_field in ['we', 'project', 'contact', 'blog', 'service', 'skill']:
            if nested_field in representation and representation[nested_field] is not None:
                representation[nested_field].pop('id', None)
                representation[nested_field].pop('created_by', None)
        return representation    
class UploadedFileSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = UploadedFile
        fields = ('id', 'file', 'uploaded_at', 'url')

    def get_url(self, obj):
        request = self.context.get('request')
        return request.build_absolute_uri(obj.file.url)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['file'] = instance.file.name.split('/')[-1]  # Keep only the filename
        return representation
 