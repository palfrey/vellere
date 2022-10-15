from notifier.cron import update_slack
import pytest

from notifier.models import GithubUser, Organisation, OrganisationUser

@pytest.mark.django_db
def test_update_slack():
    update_slack()


@pytest.mark.django_db
def test_update_slack_with_no_token():
    GithubUser.objects.create()
    update_slack()

@pytest.mark.django_db
def test_update_slack_with_broken_token():
    user = GithubUser.objects.create(username="test", oauth_token="{}")
    org = Organisation.objects.create(login="foo_org")
    org_user = OrganisationUser.objects.create(org=org, user=user)
    update_slack()
    user.refresh_from_db()
    assert user.oauth_token == ""
