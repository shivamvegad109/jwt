from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken

class User(AbstractUser):
    name = models.CharField(max_length=200)
    email = models.CharField(max_length=200, unique=True)
    password = models.CharField(max_length=255, blank=False, null=False)
    is_verified = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, null=True, blank=True)
    username = None
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']
    # first_name = models.CharField(max_length=100)
    # last_name = models.CharField(max_length=100)
    
    @property
    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            "refresh":str(refresh),
            "access":str(refresh.access_token)
        }

