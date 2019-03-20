import requests
import os

query = '''
query ($org: String!, $repo_after: String) {
  organization(login: $org) {
    repositories(first: 20, after: $repo_after, orderBy: {direction: ASC, field: NAME}) {
      edges {
        cursor
        node {
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
    "org": "lshift"
}

response = requests.post('https://api.github.com/graphql',
    headers={
        "Authorization": "bearer %s" % os.environ["BEARER_TOKEN"],
        "Accept": "application/vnd.github.vixen-preview"
        },
    json={"query":query, "variables": variables})
response.raise_for_status()

print(response.json())