"""backend URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
import json
import logging.config
import os
from logging.handlers import SMTPHandler
from subprocess import PIPE
from subprocess import Popen

from django.conf.urls import url
from django.urls import path
from pyunicore.client import Path
from rest_framework.urlpatterns import format_suffix_patterns

from backend import views
from backend.models import Service

urlpatterns = [
    path("api/health", views.Health.as_view(), name="health"),
    path("api/loglevel/<str:loglevel>", views.LogLevel.as_view()),
    path("api/job/<int:id>/", views.Job.as_view(), name="jobs"),
    path("api/job/", views.Job.as_view(), name="jobs"),
    path("api/job/<int:id>", views.Job.as_view(), name="jobs"),
    path("api/job", views.Job.as_view(), name="jobs"),
    path(
        "api/tunnel/<str:startuuidcode>/<str:servername>/<str:hostname>/<int:port2>",
        views.Tunnel.as_view(),
        name="tunnel",
    ),
    path(
        "api/tunnel/<str:startuuidcode>/<str:servername>/<str:hostname>/<int:port2>/",
        views.Tunnel.as_view(),
        name="tunnel",
    ),
    path("api/logout", views.Logout.as_view(), name="logout"),
    path("api/logout/", views.Logout.as_view(), name="logout"),
    path("api/logout/<str:stopall>", views.Logout.as_view(), name="logout"),
    path("api/logout/<str:stopall>/", views.Logout.as_view(), name="logout"),
    path("api/reservations", views.Reservations.as_view(), name="reservations"),
    path("api/reservations/", views.Reservations.as_view(), name="reservations"),
    path("api/resources", views.Resources.as_view(), name="resources"),
    path("api/resources/", views.Resources.as_view(), name="resources"),
]


def setUpLogger():
    # Who should receive the emails if an error or an exception occures?
    mail_env = os.environ.get("MAILRECEIVER", "")
    if mail_env:
        mail = mail_env.split()
    else:
        mail = []

    logger = logging.getLogger("Backend")
    # In trace will be sensitive information like tokens
    logging.addLevelName(5, "TRACE")

    def trace_func(self, message, *args, **kws):
        if self.isEnabledFor(5):
            # Yes, logger takes its '*args' as 'args'.
            self._log(5, message, args, **kws)

    logging.Logger.trace = trace_func
    mail_handler = SMTPHandler(
        mailhost=os.environ.get("MAILHOST"),
        fromaddr=os.environ.get("MAILFROM"),
        toaddrs=mail,
        subject=os.environ.get("MAILSUBJECT"),
    )
    mail_handler.setLevel(logging.ERROR)
    mail_handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] %(levelname)s in %(filename)s ( Line=%(lineno)d ): %(message)s"
        )
    )
    print("Use Logging Conf file: {}".format(os.environ.get("LOGGINGCONF")))
    logging.config.fileConfig(os.environ.get("LOGGINGCONF"))
    logger.addHandler(mail_handler)


def setUp():
    setUpLogger()


try:
    setUp()
except:
    print("Could not setup")
