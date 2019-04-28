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