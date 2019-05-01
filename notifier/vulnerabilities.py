from .helpers import run_graphql
from django.utils import timezone
from .models import Vulnerability, SlackVulnerabilitySent
import datetime

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
    while True:
        new_vulns = 0
        for data in run_graphql(github, query, variables)["repository"]["vulnerabilityAlerts"]["edges"]:
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
        if new_vulns < 20: # i.e. run out, because that's the limit
            break
        variables["vuln_after"] = cursor
    repo.vuln_updated = timezone.now()
    repo.save()
    return vulns

def repo_not_sent(link):
    max_age = timezone.now() - datetime.timedelta(days=1)
    if link.repo.vuln_updated == None or link.repo.vuln_updated < max_age:
        vulns = get_vulnerabilities(get_github(req), link.repo.org.name, link.repo.name)
    else:
        vulns = list(link.repo.vulnerability_set.all())
    sent = dict([(x.vulnerability, x) for x in SlackVulnerabilitySent.objects.filter(slack_repo=link)])
    for v in vulns:
        if v not in sent:
            yield v