from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.testclient, name='testclient'),
    url(r'^Callback/', views.testclient, name='testclient'),
]