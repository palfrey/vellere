from django.conf import settings
from requests_oauthlib import OAuth2Session
import json
from django.urls import reverse
from django.utils import timezone
from .models import *

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
    return OAuth2Session(settings.SLACK_CLIENT_ID, state=state, token=token, scope=['identify', 'chat:write:bot'], redirect_uri=redirect_uri)

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
                OrganisationUser(user=user, org=org).save()
    user.orgs_updated = timezone.now()
    user.save()
    return orgs

def get_repos(github, org):
    if org.user_organisation:
        key = "user"
        query = """
  query ($org: String!, $repo_after: String) {
    user(login: $org) {
      repositories(first: 20, after: $repo_after, orderBy: {direction: ASC, field: NAME}, affiliations: OWNER) {
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
    else:
        key = "organization"
        query = """
  query ($org: String!, $repo_after: String) {
    organization(login: $org) {
      repositories(first: 20, after: $repo_after, orderBy: {direction: ASC, field: NAME}, affiliations: OWNER) {
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
        graph = run_graphql(github, query, variables)[key]
        if graph == None:
            break
        for data in graph["repositories"]["edges"]:
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
