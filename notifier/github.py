from django.conf import settings
from requests_oauthlib import OAuth2Session
from django.shortcuts import redirect
from .models import GithubUser, Organisation, OrganisationUser
import json
from django.contrib import auth
from django.urls import reverse

authorization_base_url = 'https://github.com/login/oauth/authorize'
token_url = 'https://github.com/login/oauth/access_token'

def get_github(req, user=None):
    if user == None:
        user = req.user
    return OAuth2Session(settings.GITHUB_CLIENT_ID, token=json.loads(user.oauth_token))

def login(req):
    github = OAuth2Session(settings.GITHUB_CLIENT_ID, scope=['read:user', 'read:org', 'admin:repo_hook', 'repo'])
    authorization_url, state = github.authorization_url(authorization_base_url)

    req.session['github_oauth_state'] = state
    return redirect(authorization_url)

def callback(req):
    github = OAuth2Session(settings.GITHUB_CLIENT_ID, state=req.session['github_oauth_state'])
    token = github.fetch_token(token_url, client_secret=settings.GITHUB_CLIENT_SECRET,
                               authorization_response=req.build_absolute_uri())

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
    org.user_organisation = True
    org.save()
    try:
        OrganisationUser.objects.get(user=user, org=org)
    except OrganisationUser.DoesNotExist:
        OrganisationUser(user=user, org=org).save()

    auth.login(req, user)

    return redirect("/")

def create_webhook(req, repo):
    github = get_github(req)
    payload = {
        "name": "web",
        "active": True,
        "events": [
            "repository_vulnerability_alert",
        ],
        "config": {
            "url": req.build_absolute_uri(reverse('repository_webhook', kwargs={'org': repo.org.login, 'repo': repo.name, 'user': req.user.username})),
            "content_type": "json",
            "secret": req.user.webhook_secret,
        }
    }
    url = f"https://api.github.com/repos/{repo.org.login}/{repo.name}/hooks"
    res = github.post(url, json=payload)
    try:
        res.raise_for_status()
    except:
        raise Exception(res.json())
    return res.json()["id"]

def delete_webhook(req, repo):
    github = get_github(req)
    url = f"https://api.github.com/repos/{repo.org.login}/{repo.name}/hooks/{repo.webhook_id}"
    res = github.delete(url)
    try:
        res.raise_for_status()
    except:
        raise Exception(res.json())
