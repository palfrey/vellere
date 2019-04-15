from django.urls import path

from . import views, github, slack

urlpatterns = [
    path('', views.index, name='index'),
    path('github/login', github.login),
    path('github/callback', github.callback),
    path('slack/login<path:redir>', slack.login, name="slack_login"),
    path('slack/callback<path:redir>', slack.callback, name="slack_callback"),
    path('organisation/<str:org>', views.organisation, name="organisation"),
    path('organisation/<str:org>/<str:repo>', views.repository, name="repository"),
    path('organisation/<str:org>/<str:repo>/link', slack.repo_link, name="slack_repo_link"),
    path('slack/remove_link/<int:id>', slack.repo_link_delete, name="slack_repo_link_delete"),
]