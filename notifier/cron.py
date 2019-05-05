from .models import SlackRepoLink, SlackVulnerabilitySent
from django.utils import timezone
import datetime
from .slack import session
from .vulnerabilities import get_vulnerabilities, repo_send_for_link

def update_slack():
    max_age = timezone.now() - datetime.timedelta(days=1)
    for link in SlackRepoLink.objects.all():
        repo_send_for_link(github, link)