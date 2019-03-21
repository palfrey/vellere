from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.conf import settings
from requests_oauthlib import OAuth2Session
from .models import *
from django.contrib.auth import login
import json

def get_github(req):
    return OAuth2Session(settings.GITHUB_CLIENT_ID, token=json.loads(req.user.oauth_token))

def run_graphql(github, query):
    res = github.post('https://api.github.com/graphql',
        json={"query": query},
        headers={
            "Accept": "application/vnd.github.vixen-preview"
        })
    res.raise_for_status()
    return res.json()['data']

def get_organisations(github, user):
    data = run_graphql(github, """{
        viewer {
            organizations(first: 10) {
            edges {
                cursor
                node {
                id
                name
                viewerCanAdminister
                }
            }
            }
        }
    }
    """)
    orgs = []
    for org in data["viewer"]["organizations"]["edges"]:
        node = org["node"]
        if node["viewerCanAdminister"]:
            try:
                org = Organisation.objects.get(id=node["id"])
            except Organisation.DoesNotExist:
                org = Organisation(id=node["id"])
            org.name = node["name"]
            org.save()
            orgs.append(org)
            try:
                OrganisationUser.objects.get(user=user, org=org)
            except OrganisationUser.DoesNotExist:
                OrganisationUser.objects.create(user=user, org=org)
    return orgs

@login_required
def index(req):
    orgs = list(OrganisationUser.objects.filter(user=req.user))
    if len(orgs) == 0:
        orgs = get_organisations(get_github(req), req.user)
    return render('index', user=req.user, orgs=orgs)

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
    user.oauth_token = json.dumps(token)
    user.save()
    login(req, user)

    return redirect("/")