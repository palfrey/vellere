from django.conf import settings
from requests_oauthlib import OAuth2Session
import json

def get_github(req):
    return OAuth2Session(settings.GITHUB_CLIENT_ID, token=json.loads(req.user.oauth_token))

def run_graphql(github, query, variables={}):
    res = github.post('https://api.github.com/graphql',
        json={"query": query, "variables": variables},
        headers={
            "Accept": "application/vnd.github.vixen-preview" # Vulnerability alert preview https://developer.github.com/v4/previews/#repository-vulnerability-alerts
        })
    res.raise_for_status()
    return res.json()['data']

def session(state=None, instance=None, req=None, redir=None):
    if instance:
        token = json.loads(instance.oauth_token)
    else:
        token = None
    if req:
        redirect_uri = req.build_absolute_uri(reverse("slack_callback", args=[redir]))
    else:
        redirect_uri = None
    return OAuth2Session(settings.SLACK_CLIENT_ID, state=state, token=token, scope=['identify', 'chat:write:bot', 'channels:read', 'users:read'], redirect_uri=redirect_uri)
