from .helpers import run_graphql
from django.utils import timezone
from .models import Vulnerability, SlackVulnerabilitySent
import datetime
from .helpers import session

def get_vulnerabilities(github, org, repo):
    query = '''
query ($org: String!, $repo: String!, $vuln_after: String) {
  repository(owner: $org, name: $repo) {
    vulnerabilityAlerts(first: 20, after: $vuln_after) {
      edges {
        cursor
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
    '''
    variables = {
        "org": org.login,
        "repo": repo.name,
        "vuln_after": None
    }
    vulns = []
    existing = [x.id for x in repo.vulnerability_set.all()]
    while True:
        new_vulns = 0
        ql = run_graphql(github, query, variables)
        if ql["repository"] == None:
            # No such repo
            break
        for data in ql["repository"]["vulnerabilityAlerts"]["edges"]:
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
            vulns.append(vuln)
            cursor = data["cursor"]
            new_vulns +=1
            existing.remove(vuln.id)
        if new_vulns < 20: # i.e. run out, because that's the limit
            break
        variables["vuln_after"] = cursor
    repo.vuln_updated = timezone.now()
    repo.save()
    for id in existing:
        vuln = Vulnerability.objects.get(id=id)
        vuln.resolved = True
        vuln.save()
    return vulns

def repo_vulnerabilities(github, repo, force_update=False):
    max_age = timezone.now() - datetime.timedelta(days=1)
    if repo.vuln_updated == None or repo.vuln_updated < max_age or force_update:
        get_vulnerabilities(github, repo.org, repo)
    vulns = list(repo.vulnerability_set.filter(resolved=False))
    return vulns

# Doesn't update, because that's an expensive op
def org_vulnerabilities(github, org):
    all_vulns = []
    for repo in org.repository_set.all():
        all_vulns.extend(repo.vulnerability_set.filter(resolved=False))
    return all_vulns

def repo_sent(github, link):
    vulns = repo_vulnerabilities(github, link.repo)
    sent = [x.vulnerability for x in SlackVulnerabilitySent.objects.filter(slack_repo=link)]
    for v in vulns:
        if v in sent:
            yield v

def repo_not_sent(github, link):
    vulns = repo_vulnerabilities(github, link.repo)
    sent = repo_sent(github, link)
    for v in vulns:
        if v not in sent:
            yield v

def org_sent(github, link):
    vulns = org_vulnerabilities(github, link.org)
    sent = [x.vulnerability for x in SlackVulnerabilitySent.objects.filter(slack_org=link)]
    for v in vulns:
        if v in sent:
            yield v

def org_not_sent(github, link):
    vulns = org_vulnerabilities(github, link.org)
    sent = org_sent(github, link)
    for v in vulns:
        if v not in sent:
            yield v

def send_vuln(slack_session, v, channel):
    message = f"{v.severity} vulnerability in <{v.repo.web_url()}|{v.repo.org.login}/{v.repo.name}> package {v.package} versions '{v.vulnerableVersions}' ('{v.requirements}' required in {v.manifest_path}) <{v.url}|{v.description}>"
    res = slack_session.post("https://slack.com/api/chat.postMessage", json={
        "channel": channel,
        "text": message
    })
    res.raise_for_status()

def repo_send_for_link(github, link):
    slack_session = session(instance=link.slack)
    for v in repo_not_sent(github, link):
        send_vuln(slack_session, v, link.channel)
        SlackVulnerabilitySent(slack_repo=link, vulnerability=v).save()

def org_send_for_link(github, link):
    slack_session = session(instance=link.slack)
    sent = [x.vulnerability for x in SlackVulnerabilitySent.objects.filter(slack_org=link)]
    for repo in link.org.repository_set.all():
        for v in repo_vulnerabilities(github, repo):
            if v in sent:
                continue
            send_vuln(slack_session, v, link.channel)
            SlackVulnerabilitySent(slack_org=link, vulnerability=v).save()

def repo_update_and_send(github, repository):
    repo_vulnerabilities(github, repository, force_update=True)
    for link in repository.slackrepolink_set.all():
        repo_send_for_link(github, link)
    for link in repository.org.slackorglink_set.all():
        org_send_for_link(github, link)
