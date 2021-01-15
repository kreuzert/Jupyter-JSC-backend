import copy
import json
import logging
import os
import time
from contextlib import closing
from threading import Thread
from urllib.parse import urljoin

import requests
from django.db.utils import IntegrityError
from django.http import HttpResponse
from django.http.response import HttpResponseBadRequest
from django.http.response import HttpResponseForbidden
from django.http.response import HttpResponseNotFound
from rest_framework.views import APIView

from backend import utils
from backend.models import Service

# import the logging library

# Get an instance of a logger
log = logging.getLogger("Backend")


class LogLevel(APIView):
    def post(self, request, loglevel):
        try:
            log.trace(f"LogLevel POST: {loglevel}")
            if loglevel in ["NOTSET", "0"]:
                level = 0
            elif loglevel in ["TRACE", "5"]:
                level = 5
            elif loglevel in ["DEBUG", "10"]:
                level = 10
            elif loglevel in ["INFO", "20"]:
                level = 20
            elif loglevel in ["WARNING", "30"]:
                level = 30
            elif loglevel in ["ERROR", "40"]:
                level = 40
            elif loglevel in ["CRITICAL", "FATAL", "50"]:
                level = 50
            else:
                return HttpResponseBadRequest()
            log.setLevel(level)
            log.info(f"LogLevel switched to {level}")
            return HttpResponse(status=200)
        except:
            log.exception("Bugfix required")
            return HttpResponse(status=500)


class Health(APIView):
    def get(self, request):
        log.trace("Health check called")
        return HttpResponse(status=200)


import pyunicore.client as unicore_client
from base64 import b64encode


def send_cancel(uuidcode, user, servername, token, user_msg, msg=""):
    log.debug(
        "Call send_cancel with: {} - {} - {} - {} - {} - {}".format(
            uuidcode, user, servername, token, user_msg, msg
        )
    )
    t = Thread(
        target=_send_cancel, args=(uuidcode, user, servername, token, user_msg, msg)
    )
    t.start()


def _send_cancel(uuidcode, user, servername, token, user_msg, msg):
    wait = int(os.environ.get("CANCELSLEEP", 2))
    time.sleep(wait)
    if servername:
        path = "/".join(["users", user, "servers", servername, "cancel"])
    else:
        path = "/".join(["users", user, "server", "cancel"])
    api_url = os.environ.get("JUPYTERHUB_API_URL")
    if api_url and api_url[-1] == "/":
        url = f"{api_url}{path}"
    else:
        url = f"{api_url}/{path}"
    h = {
        "Host": os.environ.get("REQUEST_HEADER_HOST"),
        "Authorization": f"token {token}",
    }
    body = {"error": user_msg, "detail_error": msg}

    log.warning(f"uuidcode={uuidcode} Call {url} with {user_msg}")
    with closing(requests.post(url, headers=h, json=body)) as r:
        log.trace(r.status_code)
        log.trace(r.content)
        if r.status_code != 204:
            log.warning("Cancel failed")


def revoke_tokens(uuidcode, tokens):
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": os.environ.get("REQUEST_HEADER_HOST"),
    }
    url = os.environ.get("UNITY_REVOKE_URL")

    data = {"client_id": os.environ.get("UNITY_CLIENT_ID"), "logout": "true"}
    certificate = os.environ.get("UNITY_CERT_PATH", False)
    log.debug("uuidcode={} - Unity communication to revoke token.".format(uuidcode))
    for key, value in tokens.items():
        data["token_type_hint"] = key
        data["token"] = value
        log.debug(data)
        log.debug(headers)
        with closing(
            requests.post(
                url,
                headers=headers,
                data=data,
                verify=certificate,
                timeout=float(os.environ.get("UNITY_TIMEOUT", 3)),
            )
        ) as r:
            if r.status_code != 200:
                log.error(
                    "uuidcode={} - Unity communication response: {} {}".format(
                        uuidcode, r.text, r.status_code
                    )
                )
            else:
                log.trace("uuidcode={} - Unity call successful".format(uuidcode))


class Logout(APIView):
    def post(self, request, stopall="False"):
        try:
            stopall = stopall.lower() in {"true", "1"}
            uuidcode = request.headers.get("uuidcode", "<no_uuidcode>")
            accesstoken = request.headers.get("accesstoken", "")
            refreshtoken = request.headers.get("refreshtoken", "")
            tokens = {"access_token": accesstoken}
            if refreshtoken:
                tokens["refresh_token"] = refreshtoken
            username = request.headers.get("username", False)

            def logout(tokens, stopall, username):
                try:
                    if stopall and username:
                        services = Service.objects.filter(username=username).all()
                        for service in services:
                            log.debug(
                                "uuidcode={uuidcode} - Stop service {servername}".format(
                                    uuidcode=uuidcode, servername=service.servername
                                )
                            )
                            service.stop_pending = True
                            service.save()
                            service.stop(access_token=tokens["access_token"])
                            service.delete()
                    revoke_tokens(uuidcode, tokens)
                except:
                    log.exception("Oh no")

            t = Thread(target=logout, args=(tokens, stopall, username))
            t.start()
            return HttpResponse(status=204)
        except:
            log.exception("Bugfix Required")
            return HttpResponse(status=500)


class Tunnel(APIView):
    def post(self, request, startuuidcode, servername, hostname, port2):
        try:
            uuidcode = request.headers.get("uuidcode", "<no_uuidcode>")
            auth = request.headers.get("Authorization", "token None")
            try:
                token = auth.split()[1]
                if token == "None":
                    log.error(f"uuidcode={uuidcode} - Auth {auth} not allowed")
                    return HttpResponseForbidden()
            except:
                log.exception(
                    f"uuidcode={uuidcode} - Could not get Authorization header"
                )
                return HttpResponseForbidden()
            service = (
                Service.objects.filter(startuuidcode=startuuidcode)
                .filter(servername=servername)
                .first()
            )
            if not service:
                return HttpResponse(status=404)
            tunnel_url = os.environ.get("TUNNEL_URL")
            if tunnel_url and tunnel_url[-1] == "/":
                tunnel_url = tunnel_url[:-1]
            url = "/".join(
                [
                    tunnel_url,
                    servername,
                    service.remote_node,
                    hostname,
                    str(service.port),
                    str(port2),
                ]
            )
            headers = {"Host": os.environ.get("REQUEST_HEADER_HOST")}
            log.debug(f"call {url} with {headers}")
            with closing(requests.post(url, headers=headers, verify=False)) as r:
                if r.status_code != 200:
                    log.warning(r.status_code)
                    log.warning(r.content.decode("utf-8"))
                    send_cancel(
                        uuidcode,
                        service.username,
                        service.servername_short,
                        token,
                        "Could not start tunnel to service. Please try again. If this does not help contact support.",
                    )
                else:
                    if r.content.decode("utf-8") == "True":
                        pass
                    else:
                        log.warning(
                            "uuidcode={uuidcode} Tunneling answered with {ret}".format(
                                uuidcode=uuidcode, ret=r.content.decode("utf-8")
                            )
                        )
                        send_cancel(
                            uuidcode,
                            service.username,
                            service.servername_short,
                            token,
                            "Could not start tunnel to service. Please try again. If this does not help contact support.",
                        )
            return HttpResponse(status=200)
        except:
            log.exception("Bugfix required")
            return HttpResponse(status=500)


class Job(APIView):
    def get(self, request, id=-1):
        try:
            uuidcode = request.headers.get("uuidcode", "<no_uuidcode>")
            log.info(f"uuidcode={uuidcode} Get Job Status for {id}")
            service = Service.objects.filter(id=id).first()
            if not service:
                log.info(f"uuidcode={uuidcode} Service with id {id} not found.")
                response = HttpResponse("0", status=200)
            else:
                if service.stop_pending:
                    running = False
                else:
                    access_token = request.headers["Authorization"].split()[1]
                    running = service.status(uuidcode, access_token=access_token)
                log.info(f"uuidcode={uuidcode} Service is running: {running}")
                if running:
                    response = HttpResponse("None", status=200)
                else:
                    response = HttpResponse("0", status=200)
            return response
        except:
            log.exception("Bugfix required")
            return HttpResponse(status=500)

    def post(self, request):
        try:
            uuidcode = request.headers.get("uuidcode", "<no_uuidcode>")
            popen_kwargs = json.loads(request.body.decode("utf8"))
            log.info("uuidcode={uuidcode} Start Job".format(uuidcode=uuidcode))
            env = popen_kwargs.get("env")
            servername = "{}:{}".format(
                env.get("JUPYTERHUB_USER"), env.get("JUPYTERHUB_SERVER_NAME")
            )
            service = Service.objects.filter(servername=servername).first()
            if service:
                service.delete()

            service = Service.objects.create_service(uuidcode, **popen_kwargs)

            def call_start(service, retry=True):
                try:
                    service.start()
                    service.save()
                except Exception as e:
                    log.exception("Something went wrong")
                    msg = ""
                    try:
                        if isinstance(e, requests.exceptions.HTTPError):
                            unicore_config_path = os.environ.get("UNICORE_CONFIG_PATH")
                            with open(unicore_config_path, "r") as f:
                                unicore_config = json.load(f)
                            body = json.loads(e.response.text)
                            msg = body.get("errorMessage", "")

                            # Sometimes the Job start will fail because the access token is not valid anymore.
                            # This will not be detected by JupyterHub, because JupyterHub just checks the expiration
                            # time. If we receive an error from UNICORE that leads us to this, we force an token refresh
                            # and try it again. If it still fails we send a cancel request to JupyterHub.
                            if retry and msg in unicore_config.get(
                                "refresh_required", []
                            ):
                                try:
                                    token = popen_kwargs.get("env").get(
                                        "JUPYTERHUB_API_TOKEN"
                                    )
                                    api_url = os.environ.get("JUPYTERHUB_API_URL")
                                    path = "user?refresh=true"
                                    if api_url and api_url[-1] == "/":
                                        url = f"{api_url}{path}"
                                    else:
                                        url = f"{api_url}/{path}"
                                    headers = {
                                        "Host": os.environ.get("REQUEST_HEADER_HOST"),
                                        "Authorization": f"token {token}",
                                    }
                                    with closing(
                                        requests.get(url, headers=headers)
                                    ) as r:
                                        if r.status_code == 200:
                                            user_model = json.loads(
                                                r.body.decode("utf8")
                                            )
                                            service.auth_state = copy.deepcopy(
                                                user_model["auth_state"]
                                            )
                                        else:
                                            raise Exception(
                                                "Wrong status code: {}".format(
                                                    r.status_code
                                                )
                                            )
                                    call_start(service, retry=False)
                                    return
                                except:
                                    log.exception("Could not retry JobStart")
                            user_msg = msg
                            for (
                                err_message_key,
                                err_message_mapped,
                            ) in unicore_config.get("error_mapping", {}).items():
                                if msg.startswith(err_message_key):
                                    user_msg = err_message_mapped
                            if user_msg == msg:
                                log.error(f"No specific user msg for {msg}")
                        else:
                            user_msg = str(e)
                        if not user_msg:
                            user_msg = "Start failed for unknown reason"
                        token = popen_kwargs.get("env").get("JUPYTERHUB_API_TOKEN")

                        user = popen_kwargs.get("env").get("JUPYTERHUB_USER")
                        servername = popen_kwargs.get("env").get(
                            "JUPYTERHUB_SERVER_NAME"
                        )

                        send_cancel(uuidcode, user, servername, token, user_msg, msg)
                        service.delete()
                    except:
                        log.exception("Could not cancel start progress")

            t = Thread(target=call_start, args=(service,))
            t.start()

            response = HttpResponse("{id}".format(id=service.id), status=202)
            return response

        except:
            log.exception("Bugfix required")
            return HttpResponse(status=500)

    def delete(self, request, id):
        try:
            uuidcode = request.headers.get("uuidcode", "<no_uuidcode>")
            log.info(f"uuidcode={uuidcode} Stop Job for {id}")
            service = Service.objects.filter(id=id).first()
            if not service:
                log.info(f"uuidcode={uuidcode} Service with {id} not found.")
                response = HttpResponse(status=202)
            else:
                access_token = request.headers["Authorization"].split()[1]

                def stop(service, access_token):
                    try:
                        service.stop_pending = True
                        service.save()
                        service.stop(uuidcode, access_token=access_token)
                        service.delete()
                    except:
                        log.exception("Could not stop UNICORE Job")

                t = Thread(target=stop, args=(service, access_token))
                t.start()
                response = HttpResponse(status=202)
            return response
        except:
            log.exception("Bugfix required")
            return HttpResponse(status=500)


class Resources(APIView):
    def get(self, request):
        log.info("Update Resources")
        try:
            utils.update_resources()
        except:
            log.exception("Could not update resources")
        return HttpResponse(status=200)


class Reservations(APIView):
    def get(self, request):
        log.info("Update Reservation")
        try:
            utils.update_reservations()
        except:
            log.exception("Could not update reservations")
        return HttpResponse(status=200)
