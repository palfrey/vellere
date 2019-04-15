from .models import SlackRepoLink, SlackVulnerabilitySent
from django.utils import timezone
import datetime
from .slack import session

def update_slack():
    max_age = timezone.now() - datetime.timedelta(days=1)
    for link in SlackRepoLink.objects.all():
        slack_session = session(instance=link.slack)
        if link.repo.vuln_updated == None or link.repo.vuln_updated < max_age:
            vulns = views.get_vulnerabilities(get_github(req), link.repo.org.name, link.repo.name)
        else:
            vulns = list(link.repo.vulnerability_set.all())
        sent = dict([(x.vulnerability, x) for x in SlackVulnerabilitySent.objects.filter(slack=link)])
        for v in vulns:
            if v not in sent:
                message = f"{v.severity} vulnerability in {v.repo.org.name}/{v.repo.name} package {v.package}: {v.description}"
                res = slack_session.post("https://slack.com/api/chat.postMessage", json={
                    "channel": link.channel,
                    "text": message
                })
                res.raise_for_status()
                #raise Exception(message)
        raise Exception(sent)
    raise Exception