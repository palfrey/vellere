from django.db import models
from django.contrib.auth.models import User
import humanize
from django.utils import timezone

class GithubUser(models.Model):
    id = models.CharField(max_length=32, primary_key=True)
    username = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    oauth_token = models.CharField(max_length=255)
    orgs_updated = models.DateTimeField(null=True)

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

class SlackInstance(models.Model):
    team_id = models.CharField(max_length=32, primary_key=True)
    name = models.CharField(max_length=255)
    github_user = models.ForeignKey(GithubUser, on_delete=models.CASCADE)
    oauth_token = models.CharField(max_length=255)

class Organisation(models.Model):
    id = models.CharField(max_length=32, primary_key=True)
    login = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    repos_updated = models.DateTimeField(null=True)
    user_organisation = models.BooleanField(default=False)

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
    vuln_updated = models.DateTimeField(null=True)

    def vuln_info(self):
        if self.vuln_updated == None:
            return "Never updated"
        vuln_count = self.vulnerability_set.count()
        update_when = humanize.naturaltime(timezone.now() - self.vuln_updated)
        if vuln_count == 1:
            return "1 vulnerability - updated %s" % update_when
        else:
            return "%d vulnerabilities - updated %s" % (vuln_count, update_when)

    def web_url(self):
        return f"https://github.com/{self.org.login}/{self.name}"

    def __str__(self):
        return self.name

class SlackRepoLink(models.Model):
    slack = models.ForeignKey(SlackInstance, on_delete=models.CASCADE)
    repo = models.ForeignKey(Repository, on_delete=models.CASCADE)
    channel = models.CharField(max_length=255)

    def __str__(self):
        return "(%s, %s, %s)" % (self.slack.name, self.repo.name, self.channel)

    class Meta:
        indexes = [
            models.Index(fields=['slack', 'repo'], name="slack_repo_link_idx"),
        ]
        unique_together = (('slack', 'repo'))

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

class SlackVulnerabilitySent(models.Model):
    slack = models.ForeignKey(SlackRepoLink, on_delete=models.CASCADE)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)

    def __str__(self):
        return "(%s, %s)" % (self.slack.slack.name, self.vulnerability.id)

    class Meta:
        indexes = [
            models.Index(fields=['slack', 'vulnerability'], name="slack_vulnerability_idx"),
        ]
        unique_together = (('slack', 'vulnerability'))