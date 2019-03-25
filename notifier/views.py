from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.conf import settings
from requests_oauthlib import OAuth2Session
from .models import *
from django.contrib.auth import login
from django.utils import timezone
import json
import datetime

def get_github(req):
    return OAuth2Session(settings.GITHUB_CLIENT_ID, token=json.loads(req.user.oauth_token))

def run_graphql(github, query, variables={}):
    res = github.post('https://api.github.com/graphql',
        json={"query": query, "variables": variables},
        headers={
            "Accept": "application/vnd.github.vixen-preview"
        })
    res.raise_for_status()
    return res.json()['data']

def get_organisations(github, user):
    data = run_graphql(github, """
{
  viewer {
    organizations(first: 10) {
      edges {
        cursor
        node {
          id
          name
          login
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
            org.login = node["login"]
            org.save()
            orgs.append(org)
            try:
                OrganisationUser.objects.get(user=user, org=org)
            except OrganisationUser.DoesNotExist:
                OrganisationUser.objects.create(user=user, org=org)
    user.orgs_updated = timezone.now()
    user.save()
    return orgs

@login_required
def index(req):
    max_age = timezone.now() - datetime.timedelta(days=1)
    if req.user.orgs_updated == None or req.user.orgs_updated < max_age:
        orgs = get_organisations(get_github(req), req.user)
    else:
        orgs = [ou.org for ou in OrganisationUser.objects.filter(user=req.user)]
    return render(req, 'index.html', {'user': req.user, 'orgs': orgs})

def get_repos(github, org):
    query = """
query ($org: String!, $repo_after: String) {
  organization(login: $org) {
    repositories(first: 20, after: $repo_after, orderBy: {direction: ASC, field: NAME}) {
      edges {
        cursor
        node {
          id
          name
        }
      }
    }
  }
}
    """
    variables = {
        "repo_after": None,
        "org": org.login
    }
    repos = []
    while True:
        new_repos = 0
        cursor = None
        for data in run_graphql(github, query, variables)["organization"]["repositories"]["edges"]:
            node = data["node"]
            try:
                repo = Repository.objects.get(id=node["id"])
            except Repository.DoesNotExist:
                repo = Repository(id=node["id"])
            repo.org = org
            repo.name = node["name"]
            repo.save()
            repos.append(repo)
            new_repos +=1
            cursor = data["cursor"]
        if new_repos < 20: # i.e. run out, because that's the limit
            break
        variables["repo_after"] = cursor
    org.repos_updated = timezone.now()
    org.save()
    return repos

def get_vulnerabilities(github, org):
    query = '''
query ($org: String!, $repo_after: String) {
  organization(login: $org) {
    repositories(first: 20, after: $repo_after, orderBy: {direction: ASC, field: NAME}) {
      edges {
        cursor
        node {
          id
          name
          vulnerabilityAlerts(first: 20) {
            edges {
              node {
                id
                vulnerableManifestPath
                vulnerableRequirements
                dismisser {
                  id
                }
                securityVulnerability {
                  severity
                  advisory {
                    description
                    references {
                      url
                    }
                  }
                  vulnerableVersionRange
                  package {
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
    '''
    variables = {
        "repo_after": None,
        "org": org.login
    }
    repos = []
    for data in run_graphql(github, query, variables)["organization"]["repositories"]["edges"]:
        node = data["node"]
        try:
            repo = Repository.objects.get(id=node["id"])
        except Repository.DoesNotExist:
            repo = Repository(id=node["id"])
        repo.org = org
        repo.name = node["name"]
        repo.save()
        repos.append(repo)
        for data in node["vulnerabilityAlerts"]["edges"]:
            node = data["node"]
            try:
                vuln = Vulnerability.objects.get(id=node["id"])
            except Vulnerability.DoesNotExist:
                vuln = Vulnerability(id=node["id"])
            vuln.repo = repo
            vuln.manifest_path = node["vulnerableManifestPath"]
            vuln.requirements = node["vulnerableRequirements"]
            vuln.dismissed = node["dismisser"] != None
            sec = node["securityVulnerability"]
            vuln.severity = sec["severity"]
            adv = sec["advisory"]
            vuln.description = adv["description"]
            vuln.url = adv["references"][0]["url"]
            vuln.vulnerableVersions = sec["vulnerableVersionRange"]
            vuln.package = sec["package"]["name"]
            vuln.save()
    return repos

@login_required
def organisation(req, org):
    organisation = Organisation.objects.get(login=org)
    max_age = timezone.now() - datetime.timedelta(days=1)
    if organisation.repos_updated == None or organisation.repos_updated < max_age:
        repos = get_repos(get_github(req), organisation)
    else:
        repos = organisation.repository_set.all()
    return render(req, "organisation.html", {"org": org, "repos": repos})

@login_required
def repository(req, org, repo):
    raise Exception

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