from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('github/login', views.github_login),
    path('github/callback', views.github_callback),
    path('organisation/<str:org>', views.organisation, name="organisation"),
    path('organisation/<str:org>/<str:repo>', views.repository, name="repository"),
]