from django.contrib import admin
from api.models import AuthenticatedUser, DashboardUser

@admin.register(DashboardUser)
class DashboardUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'email', 'password')

@admin.register(AuthenticatedUser)
class AuthenticatedUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'status', 'user')