from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from datetime import timedelta
import random
import string
from django.urls import reverse
from django.utils.text import slugify
import uuid
from rest_framework import permissions, generics
import os

from django.db.models.signals import pre_save
class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return obj.is_public or obj.created_by == request.user
        return obj.created_by == request.user

class IsAdminUserOrOwner(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_staff:
            return True
        return request.user and view.action in ['list', 'retrieve']

    def has_object_permission(self, request, view, obj):
        if request.user and request.user.is_staff:
            return True
        return obj.created_by == request.user
class Role(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name

class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None):
        if not email:
            raise ValueError("Users must have an email address")
        if not username:
            raise ValueError("Users must have a username")
        user = self.model(
            email=self.normalize_email(email),
            username=username,
        )

        user.set_password(password)
        user.is_active = False  # Set user as inactive until they verify email
        user.save(using=self._db)
        self.assign_default_role(user)
        return user

    def create_superuser(self, email, username, first_name, last_name, password=None):
        user = self.create_user(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=password,
        )
        user.is_admin = True
        user.is_active = True
        user.save(using=self._db)
        self.assign_default_role(user, role_name='admin')
        return user

    def assign_default_role(self, user, role_name='user'):
        role, created = Role.objects.get_or_create(name=role_name)
        UserRole.objects.create(user=user, role=role)

class User(AbstractBaseUser, PermissionsMixin):
    class Gender(models.TextChoices):
        MALE = 'M', 'Male'
        FEMALE = 'F', 'Female'

    id = models.AutoField(primary_key=True)
    email = models.EmailField(verbose_name="email address", max_length=255, unique=True)
    username = models.CharField(max_length=30, unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    dob = models.DateField(blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    avatar = models.CharField(max_length=255, blank=True, null=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)  # Email verification status
    is_verified = models.BooleanField(default=False)  # Email verification status
    is_admin = models.BooleanField(default=False)
    otp_code = models.CharField(max_length=6, blank=True, null=True)
    otp_expires_at = models.DateTimeField(blank=True, null=True)
    gender = models.CharField(max_length=1, choices=Gender.choices, blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    facebook = models.URLField(blank=True, null=True)
    twitter = models.URLField(blank=True, null=True)
    instagram = models.URLField(blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin

    def set_otp(self):
        self.otp_code = ''.join(random.choices(string.digits, k=6))
        self.otp_expires_at = timezone.now() + timedelta(minutes=10)
        self.save()

    def verify_otp(self, otp_code):
        if self.otp_code == otp_code and timezone.now() < self.otp_expires_at:
            self.otp_code = None
            self.otp_expires_at = None
            self.is_verified = True
            self.is_active = True
            self.save()
            return True
        return False
    def reset_password(self, new_password):
        self.set_password(new_password)
        self.save()
class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('user', 'role')

class Contact(models.Model):
    address = models.CharField(max_length=255)
    contact_email = models.EmailField()
    phone = models.CharField(max_length=255)
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.title

class Blog(models.Model):
    id = models.AutoField(primary_key=True)
    image = models.JSONField()
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.title
class Skill(models.Model):
    image = models.JSONField()
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.title

class WorkExperience(models.Model):
    job_title = models.CharField(max_length=255)
    hired_date = models.DateTimeField()
    achievements = models.TextField()
    job_description = models.TextField()
    position = models.CharField(max_length=255)
    responsibility = models.CharField(max_length=255)
    work_address = models.CharField(max_length=255)
    company_name = models.CharField(max_length=255)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.job_title

class Service(models.Model):
    image = models.JSONField()
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.title


class Project(models.Model):
    project_title = models.CharField(max_length=255)
    project_description = models.TextField()
    link_to_project = models.CharField(max_length=255, blank=True, null=True)
    project_image = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.project_title

class Template(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class SelectTemplate(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    select_at = models.DateTimeField(auto_now_add=True)
    template = models.ForeignKey(Template, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user.username} selected {self.template.name}"

class TemplatePortfolio(models.Model):
    title = models.CharField(max_length=255)
    type = models.CharField(max_length=255)
    social_media_link_json = models.JSONField()
    portfolio_avatar = models.CharField(max_length=255, blank=True, null=True)
    biography = models.TextField()
    we = models.ForeignKey(WorkExperience, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    status = models.BooleanField(default=True)
    hero_image = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    section_image = models.CharField(max_length=255, blank=True, null=True)
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE)
    blog = models.ForeignKey(Blog, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    skill = models.ForeignKey(Skill, on_delete=models.CASCADE)
    template = models.ForeignKey(Template, on_delete=models.CASCADE)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    select_template = models.ForeignKey('SelectTemplate', on_delete=models.CASCADE, related_name='template_portfolios')
    unique_slug = models.SlugField(unique=True, blank=True, null=True)
    is_public = models.BooleanField(default=False)

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if not self.unique_slug:
            self.unique_slug = slugify(f"{self.created_by.username}-{self.title}-{uuid.uuid4().hex[:6]}")
        super().save(*args, **kwargs)
class UploadPortfolio(models.Model):
    template = models.ForeignKey(TemplatePortfolio, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField()

    def __str__(self):
        return f"{self.template.title} uploaded"

class DraftPortfolio(models.Model):
    template = models.ForeignKey(TemplatePortfolio, on_delete=models.CASCADE)
    expired_at = models.CharField(max_length=255)
    drafted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.template.title} drafted"
class UploadedFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = uuid.uuid4()
        if self.file and not self._state.adding:
            original_extension = os.path.splitext(self.file.name)[1]
            self.file.name = f"{self.id}{original_extension}"
        super().save(*args, **kwargs)

    @property
    def filename(self):
        return self.file.name

    @property
    def url(self):
        return self.file.url