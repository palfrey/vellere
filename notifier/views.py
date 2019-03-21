from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.conf import settings
from requests_oauthlib import OAuth2Session
from .models import GithubUser
from django.contrib.auth import login

@login_required
def index(req):
    raise Exception(req.user)

authorization_base_url = 'https://github.com/login/oauth/authorize'
token_url = 'https://github.com/login/oauth/access_token'

def github_login(req):
    github = OAuth2Session(settings.GITHUB_CLIENT_ID, scope=['read:user', 'read:org', 'admin:repo_hook', 'repo'])
    authorization_url, state = github.authorization_url(authorization_base_url)

    req.session['oauth_state'] = state
    return redirect(authorization_url)

def github_callback(req):
    github = OAuth2Session(settings.GITHUB_CLIENT_ID, state=req.session['oauth_state'])
    token = github.fetch_token(token_url, client_secret=settings.GITHUB_CLIENT_SECRET,
                               authorization_response=req.get_full_path())

    info = github.get('https://api.github.com/user').json()
    try:
        user = GithubUser.objects.get(id=info["node_id"])
    except GithubUser.DoesNotExist:
        user = GithubUser(id=info["node_id"])
    user.name = info["name"]
    user.username = info["login"]
    user.oauth_token = token
    user.save()
    login(req, user)

    return redirect("/")