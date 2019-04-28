from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.conf import settings
from requests_oauthlib import OAuth2Session
from .models import *
from django.contrib.auth import login
from django.utils import timezone
import datetime
from django.views.decorators.http import require_GET, require_POST
from django.urls import reverse

from .vulnerabilities import get_vulnerabilities
from .helpers import get_github, run_graphql

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
    return render(req, 'index.html', {'user': req.user, 'orgs': orgs, 'slacks': SlackInstance.objects.all()})

def get_repos(github, org):
    if org.user_organisation:
      key = "user"
      query = """
  query ($org: String!, $repo_after: String) {
    user(login: $org) {
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
    else:
      key = "organization"
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
        for data in run_graphql(github, query, variables)[key]["repositories"]["edges"]:
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

@login_required
def organisation(req, org):
    organisation = get_object_or_404(Organisation, login=org)
    max_age = timezone.now() - datetime.timedelta(days=1)
    if organisation.repos_updated == None or organisation.repos_updated < max_age:
        repos = get_repos(get_github(req), organisation)
    else:
        repos = list(organisation.repository_set.all())
    repos.sort(key=lambda x: x.name.lower())
    return render(req, "organisation.html", {"organisation": organisation, "repos": repos})

@login_required
@require_GET
def repository(req, org, repo):
    organisation = get_object_or_404(Organisation, login=org)
    repository = get_object_or_404(Repository, name=repo, org=organisation)
    max_age = timezone.now() - datetime.timedelta(days=1)
    if repository.vuln_updated == None or repository.vuln_updated < max_age:
        vulns = get_vulnerabilities(get_github(req), organisation, repository)
    else:
        vulns = list(repository.vulnerability_set.all())
    vulns.sort(key=lambda x:x.severity)
    slack_links = SlackRepoLink.objects.filter(repo=repository)
    linked_slacks = [s.slack for s in slack_links]
    slack_instances = [s for s in SlackInstance.objects.all() if s not in linked_slacks]
    return render(req, "repository.html", {"organisation": organisation, "repository": repository, "vulns": vulns, "slack_links": slack_links, "slacks": slack_instances})