from django.conf import settings
from requests_oauthlib import OAuth2Session
from django.shortcuts import redirect
from .models import SlackInstance
from django.urls import reverse
import json
from django.contrib.auth.decorators import login_required

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