from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('github/login', views.github_login),
    path('github/callback', views.github_callback),
]