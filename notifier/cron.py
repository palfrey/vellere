from .models import SlackRepoLink, SlackVulnerabilitySent
from django.utils import timezone
import datetime
from .slack import session
from .vulnerabilities import get_vulnerabilities, not_sent

def update_slack():
    max_age = timezone.now() - datetime.timedelta(days=1)
    for link in SlackRepoLink.objects.all():
        slack_session = session(instance=link.slack)
        for v in not_sent(link):
            message = f"{v.severity} vulnerability in <{v.repo.web_url()}|{v.repo.org.login}/{v.repo.name}> package {v.package} versions '{v.vulnerableVersions}' ('{v.requirements}' required in {v.manifest_path}) <{v.url}|{v.description}>"
            res = slack_session.post("https://slack.com/api/chat.postMessage", json={
                "channel": link.channel,
                "text": message
            })
            res.raise_for_status()
            SlackVulnerabilitySent(slack=link, vulnerability=v).save()