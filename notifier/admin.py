from django.contrib import admin
from .models import *

admin.site.register(GithubUser)
admin.site.register(Organisation)

class RepositoryAdmin(admin.ModelAdmin):
    list_display = ('name',)
admin.site.register(Repository, RepositoryAdmin)