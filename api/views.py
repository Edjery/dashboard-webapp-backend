import jwt

import django.contrib.auth.password_validation as validators
from django.core import exceptions
from django.conf import settings
from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.hashers import check_password

from datetime import datetime, timedelta

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework import status

from api.models import AuthenticatedUser, DashboardUser
from api.pagination import DefaultPagination
from api.serializers import AuthenticatedUserSerializer, DashboardUserSerializer

AUTH_API_URL = 'http://127.0.0.1:8000/camera/'
BASE_URL = 'http://localhost:6800/'
AUTH_URL = f'${BASE_URL}api/auth/authenticate/'

def generate_jwt_token(user_id, email, expiration_time_minutes = 30):
    expiration_time = datetime.now() + timedelta(minutes=expiration_time_minutes)
    payload = {'id': user_id, 'email': email, 'exp' : expiration_time}
    jwt_token = jwt.encode(payload, settings.JWT_SECRET, algorithm='HS256')
    return jwt_token

class UsersViewSet(ModelViewSet): 
    queryset = DashboardUser.objects.all()
    serializer_class = DashboardUserSerializer

    def create(self, request, *args, **kwargs):
        password = request.data.get('password')
    
        if password != request.data.get('confirmPassword'):
            return Response({'error' : 'password did not match'}, status=status.HTTP_400_BAD_REQUEST)          
        try:
            validators.validate_password(password)
        except exceptions.ValidationError as e:
            return Response({'error': e.messages}, status=status.HTTP_400_BAD_REQUEST)

        userInput = {
            'name': request.data.get('name'),
            'email': request.data.get('email'),
            'password': password,
        }

        serializer = DashboardUserSerializer(data=userInput)

        if serializer.is_valid():
            user = serializer.create(serializer.validated_data)
            token = generate_jwt_token(user.id, user.email)
            userData = {
                'id': user.id,
                'email': user.email,
                'name': user.name
            }
            return Response({'message': 'User registered successfully', 'token': token, 'userData': userData}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AuthenticatedUserViewSet(ModelViewSet): 
    queryset = AuthenticatedUser.objects.all()
    serializer_class = AuthenticatedUserSerializer
    pagination_class = DefaultPagination
    
@api_view(['POST'])
def login_user(request):
    if request.method == 'POST':
        email = request.data.get('email')
        password = request.data.get('password')
        user = get_object_or_404(DashboardUser, email=email)

        if user and check_password(password, user.password):
            token = generate_jwt_token(user.id, user.email)
            userData = {
                'id': user.id,
                'email': user.email,
                'name': user.name
            }

            exists = AuthenticatedUser.objects.filter(user=user).exists()
            if exists:
                auth_user = get_object_or_404(AuthenticatedUser, user=user)
                if auth_user.status:
                    email = user.email
                    redirect_url = AUTH_URL

                    redirect_url_with_params = f"{AUTH_API_URL}?email={email}&redirect_url={redirect_url}"
                    return Response({'mode': 'auth', 'message': 'User sign in successfully', 'redirect_url' : redirect_url_with_params}, status=status.HTTP_200_OK)
                        
            return Response({'mode': 'signin', 'message': 'User sign in successfully', 'token' : token, 'userData' : userData}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

client_code = 'secretcodexyz'
front_end_url = 'http://localhost:2776/'
token_url = f'{front_end_url}auth'

@api_view(['GET'])
def authenticate(request):
    if request.method == 'GET':
        code = request.GET.get('code')
        token = request.GET.get('token')

        if code and token:
            if code == client_code:
                redirect_url = f'{token_url}?token={token}'
                return redirect(redirect_url)
            else:
                return Response({'error': 'Invalid code or token'}, status=400)
        else:
            return Response({'error': 'Both code and token are required'}, status=400)
    else:
        return Response({'error': 'Only GET method is allowed'}, status=405)

@api_view(['POST'])
def authenticate_with_token(request):
    print('authenticating with token...')
    if request.method == 'POST':
        token = request.data.get('token')
        print('token:', token)
        decoded_token = jwt.decode(token, 'your_secret_key_here', algorithms=['HS256'])
        print('decoded_token:', decoded_token)
        
        email = decoded_token['email']
        print('email:', email)
        user = get_object_or_404(DashboardUser, email=email)

        userData = {
            'id': user.id,
            'email': user.email,
            'name': user.name
        }

        return Response({'message': 'User sign in successfully', 'token' : token, 'userData' : userData}, status=status.HTTP_201_CREATED)
    else:
        return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
