from django.db import models

class DashboardUser(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=50)

    def __str__(self) -> str:
        return self.email

class AuthenticatedUser(models.Model):
    status = models.BooleanField(default=True)
    user = models.OneToOneField(DashboardUser, on_delete=models.CASCADE)

    def __str__(self) -> str:
        return self.user.name
