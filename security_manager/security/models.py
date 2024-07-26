from django.db import models

class Vulnerability(models.Model):
    vul_id = models.CharField(max_length=100, unique=True)
    vulnStatus = models.CharField(max_length=10)

    def __str__(self):
        return self.vul_id
