from django.db import models
from django.contrib.auth.models import User

class GithubUser(models.Model):
    id = models.CharField(max_length=32, primary_key=True)
    username = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    oauth_token = models.CharField(max_length=255)
    REQUIRED_FIELDS = []
    USERNAME_FIELD = "username"

    def __str__(self):
        return "Github User: %s" % self.username

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True

class Organisation(models.Model):
    id = models.CharField(max_length=32, primary_key=True)
    login = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class OrganisationUser(models.Model):
    user = models.ForeignKey(GithubUser, on_delete=models.CASCADE)
    org = models.ForeignKey(Organisation, on_delete=models.CASCADE)

    def __str__(self):
        return "(%s, %s)" % (self.user.name, self.org.name)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'org'], name="organisation_user_idx"),
        ]
        unique_together = (('user', 'org'))

class Repository(models.Model):
    id = models.CharField(max_length=32, primary_key=True)
    org = models.ForeignKey(Organisation, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Vulnerability(models.Model):
    id = models.CharField(max_length=64, primary_key=True)
    repo = models.ForeignKey(Repository, on_delete=models.CASCADE)
    manifest_path = models.CharField(max_length=255)
    requirements = models.CharField(max_length=64)
    dismissed = models.BooleanField()
    severity = models.CharField(max_length=8, choices=(("LOW", "Low"), ("MODERATE", "Moderate"), ("HIGH", "High"), ("CRITICAL", "Critical")))
    description = models.TextField()
    url = models.URLField()
    vulnerableVersions = models.CharField(max_length=64)
    package = models.CharField(max_length=255)
