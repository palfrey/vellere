from .models import Organisation, OrganisationUser
from .github import get_github
from .vulnerabilities import repo_update_and_send

def update_slack():
    for org in Organisation.objects.all():
        org_user = OrganisationUser.objects.filter(org=org).first()
        github = get_github(None, org_user.user)
        for repo in org.repository_set.all():
            print("Updating: %s - %s" % (org.login, repo))
            repo_update_and_send(github, repo, force_update=False) # Only update if out of date