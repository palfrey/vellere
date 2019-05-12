from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.conf import settings
from requests_oauthlib import OAuth2Session
from .models import *
from django.contrib.auth import login
from django.utils import timezone
import datetime
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.db.models import Count

from .vulnerabilities import repo_vulnerabilities, repo_not_sent, repo_send_for_link, repo_sent, org_not_sent, org_sent, org_send_for_link, repo_update_and_send
from .helpers import run_graphql
from . import github
import hashlib
import hmac
import urllib.parse as parse

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

@login_required
@require_http_methods(["GET", "POST"])
def index(req):
    max_age = timezone.now() - datetime.timedelta(days=1)
    if req.user.orgs_updated == None or req.user.orgs_updated < max_age or req.method == "POST":
        get_organisations(github.get_github(req), req.user)
        return redirect(reverse("index"))
    orgs = [ou.org for ou in OrganisationUser.objects.select_related("org").filter(user=req.user, org__user_organisation=False)]
    orgs.sort(key=lambda o: o.name.lower())
    all_orgs = orgs + [Organisation.objects.get(login=req.user.username)]
    org_links = SlackOrgLink.objects.filter(org__in=all_orgs)
    repo_links = SlackRepoLink.objects.filter(repo__org__in=all_orgs)
    return render(req, 'index.html', {
        'user': req.user,
        'orgs': orgs,
        'slacks': SlackInstance.objects.all(),
        'org_links': org_links,
        'repo_links': repo_links
    })

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

def has_access_to_org(func):
    def wrapper(req, *args, **kwargs):
        if "org" not in kwargs:
            raise Exception("Missing 'org' keyword arg")
        get_object_or_404(OrganisationUser, org__login=kwargs['org'], user=req.user)
        return func(req, *args, **kwargs)
    return wrapper

def has_access_to_repo(func):
    def wrapper(req, *args, **kwargs):
        if "org" not in kwargs:
            raise Exception("Missing 'org' keyword arg")
        if "repo" not in kwargs:
            raise Exception("Missing 'repo' keyword arg")
        org_user = get_object_or_404(OrganisationUser, org__login=kwargs['org'], user=req.user)
        get_object_or_404(Repository, org=org_user.org, name=kwargs['repo'])
        return func(req, *args, **kwargs)
    return wrapper

@require_http_methods(["GET", "POST"])
@has_access_to_org
def organisation(req, org=None):
    organisation = get_object_or_404(Organisation, login=org)
    max_age = timezone.now() - datetime.timedelta(days=1)
    if req.method == "POST":
        get_repos(github.get_github(req), organisation)
        return redirect(reverse('organisation', kwargs={'org': organisation.login}))
    if organisation.repos_updated == None or organisation.repos_updated < max_age or req.method == "POST":
        get_repos(github.get_github(req), organisation)
    repos = list(organisation.repository_set.annotate(Count('vulnerability', resolved=False)))
    sort = req.GET.get('sort', 'name')
    if sort == 'vulnerabilities':
        repos.sort(key=lambda x: x.vuln_count, reverse=True)
    else: # default to sort by name
        repos.sort(key=lambda x: x.name.lower())
    slack_links = SlackOrgLink.objects.filter(org=organisation)
    linked_slacks = [s.slack for s in slack_links]
    slack_instances = [s for s in SlackInstance.objects.all() if s not in linked_slacks]
    sorts = ["name", "vulnerabilities"]
    sort_links = {}
    for sort_option in sorts:
        if sort == sort_option:
            sort_links[sort_option] = sort_option
        else:
            parsed = parse.urlparse(req.get_full_path())
            query = parse.parse_qs(parsed.query)
            query['sort'] = sort_option
            url = parse.urlunparse(parsed._replace(query=parse.urlencode(query)))
            sort_links[sort_option] = "<a href=\"%s\">%s</a>" % (url, sort_option)
    sort_links = " / ".join(sort_links.values())
    return render(req, "organisation.html", {
        "organisation": organisation,
        "repos": repos,
        "slacks": slack_instances,
        "slack_links": slack_links,
        "sort_links": sort_links})

@login_required
@require_http_methods(["GET", "POST"])
@has_access_to_org
@has_access_to_repo
def repository(req, org=None, repo=None):
    organisation = get_object_or_404(Organisation, login=org)
    repository = get_object_or_404(Repository, name=repo, org=organisation)
    github_session = github.get_github(req)
    if req.method == "POST":
        repo_update_and_send(github_session, repository)
        return redirect(reverse('repository', kwargs={'org': organisation.login, 'repo': repository.name}))
    vulns = repo_vulnerabilities(github_session, repository)
    vulns.sort(key=lambda x:x.severity)
    old_vulns = list(repository.vulnerability_set.filter(resolved=True))
    repo_slack_links = SlackRepoLink.objects.filter(repo=repository)
    org_slack_links = SlackOrgLink.objects.filter(org=organisation)
    linked_slacks = [s.slack for s in repo_slack_links]
    slack_instances = [s for s in SlackInstance.objects.all() if s not in linked_slacks]
    return render(req, "repository.html", {
        "organisation": organisation,
        "repository": repository,
        "vulns": vulns,
        "old_vulns": old_vulns,
        "org_slack_links": org_slack_links,
        "repo_slack_links": repo_slack_links,
        "slacks": slack_instances})

def has_access_to_org_link(func):
    def wrapper(req, id):
        link = get_object_or_404(SlackOrgLink, id=id)
        get_object_or_404(OrganisationUser, org=link.org, user=req.user)
        return func(req, id)
    return wrapper

def has_access_to_repo_link(func):
    def wrapper(req, id):
        link = get_object_or_404(SlackRepoLink, id=id)
        get_object_or_404(OrganisationUser, org=link.repo.org, user=req.user)
        return func(req, id)
    return wrapper

@login_required
@require_GET
@has_access_to_org_link
def org_link(req, id):
    link = get_object_or_404(SlackOrgLink, id=id)
    github_session = github.get_github(req)
    missing = org_not_sent(github_session, link)
    return render(req, "org_link.html", {"link": link, "missing": missing, "sent": org_sent(github_session, link)})

@login_required
@require_POST
@has_access_to_org_link
def update_org_link(req, id):
    link = get_object_or_404(SlackOrgLink, id=id)
    github_session = github.get_github(req)
    org_send_for_link(github_session, link)
    return redirect(reverse('slack_org_link_info', kwargs={'id': id}))

@login_required
@require_GET
@has_access_to_repo_link
def repo_link(req, id):
    link = get_object_or_404(SlackRepoLink, id=id)
    github_session = github.get_github(req)
    missing = repo_not_sent(github_session, link)
    return render(req, "repo_link.html", {"link": link, "missing": missing, "sent": repo_sent(github_session, link)})

@login_required
@require_POST
@has_access_to_repo_link
def update_repo_link(req, id):
    link = get_object_or_404(SlackRepoLink, id=id)
    github_session = github.get_github(req)
    repo_send_for_link(github_session, link)
    return redirect(reverse('slack_repo_link_info', kwargs={'id': id}))

@login_required
@require_POST
@has_access_to_org
@has_access_to_repo
def add_repo_webhook(req, org=None, repo=None):
    organisation = get_object_or_404(Organisation, login=org)
    repository = get_object_or_404(Repository, name=repo, org=organisation)
    if repository.webhook_id == None:
        repository.webhook_id = github.create_repo_webhook(req, repository)
        repository.save()
    return redirect(reverse('repository', kwargs={'org': organisation.login, 'repo': repository.name}))

@login_required
@require_POST
@has_access_to_org
@has_access_to_repo
def delete_repo_webhook(req, org=None, repo=None):
    organisation = get_object_or_404(Organisation, login=org)
    repository = get_object_or_404(Repository, name=repo, org=organisation)
    if repository.webhook_id != None:
        github.delete_repo_webhook(req, repository)
        repository.webhook_id = None
        repository.save()
    return redirect(reverse('repository', kwargs={'org': organisation.login, 'repo': repository.name}))

@csrf_exempt
def repository_webhook(req, org, repo, user):
    user = get_object_or_404(GithubUser, username=user)
    hash = "sha1=%s" % hmac.new(user.webhook_secret.encode('utf-8'), req.body, hashlib.sha1).hexdigest()
    if "HTTP_X_HUB_SIGNATURE" not in req.META:
        return HttpResponseBadRequest("No X-Hub-Signature header")
    header = req.META["HTTP_X_HUB_SIGNATURE"]
    if header != hash:
        return HttpResponseBadRequest("%s doesn't equal %s" % (hash, header))
    github_session = github.get_github(req, user)
    organisation = get_object_or_404(Organisation, login=org)
    repository = get_object_or_404(Repository, name=repo, org=organisation)
    repo_update_and_send(github_session, repository)
    return HttpResponse()

@login_required
@require_POST
@has_access_to_org
def add_org_webhook(req, org=None):
    organisation = get_object_or_404(Organisation, login=org)
    if organisation.webhook_id == None:
        organisation.webhook_id = github.create_org_webhook(req, organisation)
        organisation.save()
    return redirect(reverse('organisation', kwargs={'org': organisation.login}))

@login_required
@require_POST
@has_access_to_org
def delete_org_webhook(req, org=None, repo=None):
    organisation = get_object_or_404(Organisation, login=org)
    if organisation.webhook_id != None:
        github.delete_org_webhook(req, organisation)
        organisation.webhook_id = None
        organisation.save()
    return redirect(reverse('organisation', kwargs={'org': organisation.login}))

@csrf_exempt
def organisation_webhook(req, org, user):
    user = get_object_or_404(GithubUser, username=user)
    hash = "sha1=%s" % hmac.new(user.webhook_secret.encode('utf-8'), req.body, hashlib.sha1).hexdigest()
    if "HTTP_X_HUB_SIGNATURE" not in req.META:
        return HttpResponseBadRequest("No X-Hub-Signature header")
    header = req.META["HTTP_X_HUB_SIGNATURE"]
    if header != hash:
        return HttpResponseBadRequest("%s doesn't equal %s" % (hash, header))
    github_session = github.get_github(req, user)
    org = get_object_or_404(Organisation, login=org)
    for repo in org.repository_set.all():
        repo_update_and_send(github_session, repo)
    return HttpResponse()