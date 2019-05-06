from django.conf import settings
from requests_oauthlib import OAuth2Session
from django.shortcuts import redirect, get_object_or_404
from .models import SlackInstance, SlackOrgLink, SlackRepoLink, Organisation, Repository
from django.urls import reverse
import json
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST, require_http_methods
from django.http import HttpResponse
from .vulnerabilities import repo_send_for_link
from .helpers import session
from .github import get_github

authorization_base_url = 'https://slack.com/oauth/authorize'
token_url = 'https://slack.com/api/oauth.access'

@login_required
def login(req, redir):
    slack = session(req=req, redir=redir)
    authorization_url, state = slack.authorization_url(authorization_base_url)
    req.session['slack_oauth_state'] = state
    return redirect(authorization_url)

@login_required
def callback(req, redir):
    slack = session(state=req.session['slack_oauth_state'], req=req, redir=redir)
    token = slack.fetch_token(token_url, client_secret=settings.SLACK_CLIENT_SECRET,
                               authorization_response=req.get_full_path())

    info = slack.get('https://slack.com/api/auth.test').json()
    try:
        instance = SlackInstance.objects.get(team_id=info["team_id"])
    except SlackInstance.DoesNotExist:
        instance = SlackInstance(team_id=info["team_id"])
    instance.github_user = req.user
    instance.name = info["team"]
    instance.url = info["url"]
    instance.oauth_token = json.dumps(token)
    instance.save()

    return redirect(redir)

@login_required
@require_POST
def org_link(req, org):
    organisation = get_object_or_404(Organisation, login=org)
    slack = get_object_or_404(SlackInstance, team_id=req.POST["slack"])
    SlackOrgLink(org=organisation, slack=slack, channel=req.POST["channel"]).save()
    return redirect(reverse('organisation', kwargs={'org': organisation.login}))

@login_required
@require_http_methods(["DELETE"])
def org_link_delete(req, id):
    get_object_or_404(SlackOrgLink, id=id).delete()
    return HttpResponse(status=204)

@login_required
@require_POST
def repo_link(req, org, repo):
    organisation = get_object_or_404(Organisation, login=org)
    repository = get_object_or_404(Repository, name=repo, org=organisation)
    slack = get_object_or_404(SlackInstance, team_id=req.POST["slack"])
    link = SlackRepoLink(repo=repository, slack=slack, channel=req.POST["channel"])
    link.save()
    repo_send_for_link(get_github(req), link)
    return redirect(reverse('repository', kwargs={'org': organisation.login, 'repo': repository.name}))

@login_required
@require_http_methods(["DELETE"])
def repo_link_delete(req, id):
    get_object_or_404(SlackRepoLink, id=id).delete()
    return HttpResponse(status=204)