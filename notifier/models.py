from django.db import models
from django.contrib.auth.models import User
import humanize
from django.utils import timezone
import secrets
from django.conf import settings

class GithubUser(models.Model):
    id = models.CharField(max_length=32, primary_key=True)
    username = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    oauth_token = models.CharField(max_length=255)
    orgs_updated = models.DateTimeField(null=True)
    webhook_secret = models.CharField(max_length=32, default=secrets.token_urlsafe)

    REQUIRED_FIELDS = []
    USERNAME_FIELD = "username"

    def last_updated(self):
        return humanize.naturaltime(timezone.now() - self.orgs_updated)

    def __str__(self):
        return "Github User: %s" % self.username

    @property
    def is_anonymous(self):
        return False

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_staff(self):
        return self.is_superuser

    @property
    def is_superuser(self):
        return self.username == settings.SUPERUSER_LOGIN

    def has_module_perms(self, module):
        return self.is_superuser

    def has_perm(self, perm, object=None):
        return self.is_superuser

    def get_username(self):
        return self.username

class SlackInstance(models.Model):
    team_id = models.CharField(max_length=32, primary_key=True)
    url = models.URLField()
    name = models.CharField(max_length=255)
    github_user = models.ForeignKey(GithubUser, on_delete=models.CASCADE)
    oauth_token = models.CharField(max_length=255)

class Organisation(models.Model):
    id = models.CharField(max_length=32, primary_key=True)
    login = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    repos_updated = models.DateTimeField(null=True)
    user_organisation = models.BooleanField(default=False)

    def last_updated(self):
        return humanize.naturaltime(timezone.now() - self.repos_updated)

    def __str__(self):
        return self.name

class SlackOrgLink(models.Model):
    slack = models.ForeignKey(SlackInstance, on_delete=models.CASCADE)
    org = models.ForeignKey(Organisation, on_delete=models.CASCADE)
    channel = models.CharField(max_length=255)

    def __str__(self):
        return "(%s, %s, %s)" % (self.slack.name, self.org.login, self.channel)

    class Meta:
        indexes = [
            models.Index(fields=['slack', 'org'], name="slack_org_link_idx"),
        ]
        unique_together = (('slack', 'org'))

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
    webhook_id = models.IntegerField(null=True)

    def vuln_info(self):
        if self.vuln_updated == None:
            return "Never updated"
        vuln_count = self.vulnerability_set.count()
        update_when = self.last_update()
        if vuln_count == 1:
            return "1 vulnerability - updated %s" % update_when
        else:
            return "%d vulnerabilities - updated %s" % (vuln_count, update_when)

    def last_update(self):
        if self.vuln_updated == None:
            return "Never updated"
        return humanize.naturaltime(timezone.now() - self.vuln_updated)

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
    resolved = models.BooleanField(default=False)

    def __str__(self):
        try:
            safe_desc = self.description.replace("{", "{{").replace("}", "}}")
            return f"{self.severity}: {self.package} versions '{self.vulnerableVersions}' ('{self.requirements}' required in {self.manifest_path}) has <a href=\"{self.url}\">{safe_desc}</a>".format(self=self, safe_desc=safe_desc)
        except IndexError:
            raise Exception(self.__dict__)

class SlackVulnerabilitySent(models.Model):
    slack_org = models.ForeignKey(SlackOrgLink, on_delete=models.CASCADE, null=True)
    slack_repo = models.ForeignKey(SlackRepoLink, on_delete=models.CASCADE, null=True)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)

    def __str__(self):
        slack = self.slack_org if self.slack_org != None else self.slack_repo
        return "(%s, %s)" % (slack.slack.name, self.vulnerability.id)

    class Meta:
        indexes = [
            models.Index(fields=['slack_org', 'vulnerability'], name="slack_vulnerability_org_idx"),
            models.Index(fields=['slack_repo', 'vulnerability'], name="slack_vulnerability_repo_idx"),
        ]