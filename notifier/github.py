from django.conf import settings
from requests_oauthlib import OAuth2Session
from django.shortcuts import redirect
from .models import GithubUser, Organisation
import json
from django.contrib import auth

authorization_base_url = 'https://github.com/login/oauth/authorize'
token_url = 'https://github.com/login/oauth/access_token'

def login(req):
    github = OAuth2Session(settings.GITHUB_CLIENT_ID, scope=['read:user', 'read:org', 'admin:repo_hook', 'repo'])
    authorization_url, state = github.authorization_url(authorization_base_url)

    req.session['github_oauth_state'] = state
    return redirect(authorization_url)

def callback(req):
    github = OAuth2Session(settings.GITHUB_CLIENT_ID, state=req.session['github_oauth_state'])
    token = github.fetch_token(token_url, client_secret=settings.GITHUB_CLIENT_SECRET,
                               authorization_response=req.get_full_path())

    info = github.get('https://api.github.com/user').json()

    try:
        user = GithubUser.objects.get(id=info["node_id"])
    except GithubUser.DoesNotExist:
        user = GithubUser(id=info["node_id"])
    user.name = info["name"]
    user.username = info["login"]
    user.oauth_token = json.dumps(token)
    user.save()

    try:
        org = Organisation.objects.get(id=info["node_id"])
    except Organisation.DoesNotExist:
        org = Organisation(id=info["node_id"])
    org.login = info["login"]
    org.name = info["name"]
    org.save()

    auth.login(req, user)

    return redirect("/")
