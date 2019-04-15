from django.conf import settings
from requests_oauthlib import OAuth2Session
from django.shortcuts import redirect, get_object_or_404
from .models import SlackInstance, SlackRepoLink
from django.urls import reverse
import json
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST, require_http_methods
from django.http import HttpResponse

authorization_base_url = 'https://slack.com/oauth/authorize'
token_url = 'https://slack.com/api/oauth.access'

@login_required
def login(req, redir):
    slack = OAuth2Session(settings.SLACK_CLIENT_ID, scope=['chat:write:bot', 'channels:read', 'users:read'], redirect_uri=req.build_absolute_uri(reverse("slack_callback", args=[redir])))
    authorization_url, state = slack.authorization_url(authorization_base_url)
    req.session['slack_oauth_state'] = state
    return redirect(authorization_url)

@login_required
def callback(req, redir):
    slack = OAuth2Session(settings.SLACK_CLIENT_ID, state=req.session['slack_oauth_state'], redirect_uri=req.build_absolute_uri(reverse("slack_callback", args=[redir])))
    token = slack.fetch_token(token_url, client_secret=settings.SLACK_CLIENT_SECRET,
                               authorization_response=req.get_full_path())

    info = slack.get('https://slack.com/api/auth.test').json()
    try:
        instance = SlackInstance.objects.get(team_id=info["team_id"])
    except SlackInstance.DoesNotExist:
        instance = SlackInstance(team_id=info["team_id"])
    instance.github_user = req.user
    instance.name = info["team"]
    instance.oauth_token = json.dumps(token)
    instance.save()

    return redirect("/%s" % redir)

@login_required
@require_POST
def repo_link(req, org, repo):
    organisation = get_object_or_404(Organisation, login=org)
    repository = get_object_or_404(Repository, name=repo, org=organisation)
    slack = get_object_or_404(SlackInstance, team_id=req.POST["slack"])
    SlackRepoLink(repo=repository, slack=slack, channel=req.POST["channel"]).save()
    return redirect(reverse('repository', kwargs={'org': organisation.login, 'repo': repository.name}))

@login_required
@require_http_methods(["DELETE"])
def repo_link_delete(req, id):
    get_object_or_404(SlackRepoLink, id=id).delete()
    return HttpResponse(status=204)