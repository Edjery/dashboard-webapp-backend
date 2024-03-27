from django.db import models

class DashboardUser(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=50)

    def __str__(self) -> str:
        return self.email
