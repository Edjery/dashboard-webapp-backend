from django.contrib import admin
from api.models import DashboardUser

@admin.register(DashboardUser)
class DashboardUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'email', 'password')