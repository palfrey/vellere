from django.urls import path

from . import views, github, slack

urlpatterns = [
    path('', views.index, name='index'),
    path('github/login', github.login),
    path('github/callback', github.callback),
    path('slack/login<path:redir>', slack.login, name="slack_login"),
    path('slack/callback<path:redir>', slack.callback, name="slack_callback"),
    path('organisation/<str:org>', views.organisation, name="organisation"),
    path('organisation/<str:org>/link', slack.org_link, name="slack_org_link"),
    path('organisation/<str:org>/<str:repo>', views.repository, name="repository"),
    path('organisation/<str:org>/<str:repo>/webhook/<str:user>', views.repository_webhook, name="repository_webhook"),
    path('organisation/<str:org>/<str:repo>/webhook_add', views.add_repo_webhook, name="add_repository_webhook"),
    path('organisation/<str:org>/<str:repo>/webhook_delete', views.delete_repo_webhook, name="delete_repository_webhook"),
    path('organisation/<str:org>/<str:repo>/link', slack.repo_link, name="slack_repo_link"),
    path('slack/remove_repo_link/<int:id>', slack.org_link_delete, name="slack_org_link_delete"),
    path('slack/remove_org_link/<int:id>', slack.repo_link_delete, name="slack_repo_link_delete"),
    path('slack/org_link/<int:id>', views.org_link, name="slack_org_link_info"),
    path('slack/org_link/<int:id>/update', views.update_org_link, name="slack_org_link_update"),
    path('slack/repo_link/<int:id>', views.repo_link, name="slack_repo_link_info"),
    path('slack/repo_link/<int:id>/update', views.update_repo_link, name="slack_repo_link_update"),
]