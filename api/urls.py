from . import views
from django.urls import path

from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register('users', views.UsersViewSet)

urlpatterns =  [
    path('login/', views.login_user , name='login_user'),
    path('auth/authenticate/', views.authenticate , name='authenticate'),
    path('auth/authenticate_user/', views.authenticate_with_token , name='authenticate_user'),
] + router.urls