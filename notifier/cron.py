from .models import Organisation, OrganisationUser, GithubUser
from .github import get_github
from .vulnerabilities import repo_update_and_send
from django.utils import timezone
import datetime
from .helpers import get_organisations, get_repos
from .github import get_github
import requests

def update_slack():
    max_age = timezone.now() - datetime.timedelta(days=1)
    for user in GithubUser.objects.all():
        if user.orgs_updated == None or user.orgs_updated < max_age:
            print("Updating orgs for user %s" % user.username)
            github = get_github(None, user)
            if github is None:
                print("No token for %s", user.username)
                continue
            try:
                get_organisations(github, user)
            except requests.HTTPError as e:
                if e.response.status_code == 401:
                    print("Bad token for %s, clearing" % user.username)
                    user.oauth_token = ""
                    user.save()
                else:
                    raise

    for org in Organisation.objects.all():
        org_user = OrganisationUser.objects.filter(org=org).first()
        github = get_github(None, org_user.user)
        if github is None:
            print("No token for %s" % org_user.user.username)
            continue

        if org.repos_updated == None or org.repos_updated < max_age:
            print("Updating repos for %s" % org.login)
            get_repos(github, org)
        for repo in org.repository_set.all():
            print("Updating: %s - %s" % (org.login, repo))
            repo_update_and_send(github, repo, force_update=False) # Only update if out of date