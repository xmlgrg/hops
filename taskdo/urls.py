from django.conf.urls import url

from taskdo.views import *

urlpatterns = [
    url(r'^adhocdo/', adhoc_task),
    url(r'^adhoclog', adhoc_task_log)
]
