from django.contrib.auth.hashers import make_password
from django.contrib.auth import password_validation
from django.core import exceptions

from rest_framework.exceptions import ValidationError
from rest_framework import serializers
from rest_framework import status

from api.models import AuthenticatedUser, DashboardUser

class DashboardUserSerializer(serializers.ModelSerializer):
    def create(self, validated_data):
        if 'password' in validated_data:
            validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)

    def update(self, instance, validated_data):
        if 'password' in validated_data:
            password = validated_data['password']

            try:
                password_validation.validate_password(password)
            except exceptions.ValidationError as e:
                raise ValidationError(detail={'error': e.messages}, code=status.HTTP_400_BAD_REQUEST)

            validated_data['password'] = make_password(password)
        return super().update(instance, validated_data)
     
    class Meta:
        model = DashboardUser
        fields = ['id', 'name', 'email', 'password',]


class AuthenticatedUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthenticatedUser
        fields = ['user', 'status']

