import copy
import json
import logging
import os
import random
import time
import urllib.parse
from contextlib import closing
from datetime import datetime
from pathlib import Path

import pyunicore.client as unicore_client
import requests
from django.db import models


log = logging.getLogger("Backend")


class ServiceManager(models.Manager):
    def create_service(self, uuidcode, **kwargs):
        log.trace(
            "uuidcode={uuidcode} Create Service with {kwargs}".format(
                uuidcode=uuidcode, kwargs=kwargs
            )
        )
        startuuidcode = uuidcode
        port = kwargs.pop("port")
        env = kwargs.pop("env")
        user_options = kwargs.pop("user_options")
        auth_state = kwargs.pop("auth_state")
        username = env.get("JUPYTERHUB_USER")
        servername_short = env.get("JUPYTERHUB_SERVER_NAME")
        servername = f"{username}:{servername_short}"
        servicetype = user_options.get("service_input")
        system = user_options.get("system_input")
        account = user_options.get("account_input")
        project = user_options.get("project_input")
        partition = user_options.get("partition_input")
        service = self.create(
            startuuidcode=startuuidcode,
            servername=servername,
            username=username,
            servername_short=servername_short,
            servicetype=servicetype,
            system=system,
            account=account,
            project=project,
            partition=partition,
            port=port,
        )

        config_base_path = os.environ.get("CONFIG_BASE_PATH")
        unicore_config_path = os.environ.get("UNICORE_CONFIG_PATH")
        with open(unicore_config_path, "r") as f:
            unicore_config = json.load(f)
        service.set_memory_variables(
            env=env,
            auth_state=auth_state,
            user_options=user_options,
            unicore_config=unicore_config,
            config_base_path=config_base_path,
        )
        return service


class Service(models.Model):
    startuuidcode = models.TextField(null=False, max_length=40)
    servername = models.TextField(null=False, max_length=400)
    username = models.TextField(null=False, max_length=250)
    stop_pending = models.BooleanField(null=False, default=False)
    servername_short = models.TextField(null=False, max_length=150)
    servicetype = models.TextField(null=False, max_length=50)
    system = models.TextField(null=False, max_length=50)
    dockerimage = models.TextField(null=True, max_length=50)
    account = models.TextField(null=True, max_length=50)
    project = models.TextField(null=True, max_length=50)
    partition = models.TextField(null=True, max_length=50)
    port = models.IntegerField(null=False)
    remote_node = models.TextField(null=True, max_length=100)
    resource_url = models.TextField(null=True, max_length=400)
    date = models.DateTimeField(auto_now=True)

    # Memory values for start
    auth_state = {}
    env = {}
    user_options = {}
    unicore_config = {}
    job_description = {}

    def set_memory_variables(
        self, env, auth_state, user_options, unicore_config, config_base_path
    ):
        self.env = env
        self.auth_state = auth_state
        self.user_optins = user_options
        self.unicore_config = unicore_config
        self.config_base_path = config_base_path
        self.service_base_path = os.path.join(config_base_path, self.servicetype)

    objects = ServiceManager()

    def get_active_remote_node(self, _remote_nodes):
        startuuidcode = self.startuuidcode
        remote_nodes = copy.deepcopy(_remote_nodes)
        log.trace(
            f"uuidcode={startuuidcode} Looking for active node in list {remote_nodes}"
        )
        remote_url = os.environ.get("TUNNEL_REMOTE_NODE_URL")
        log.trace(f"uuidcode={startuuidcode} Tunnel remote url: {remote_url}")
        h = {"Host": os.environ.get("REQUEST_HEADER_HOST"), "uuidcode": startuuidcode}
        while len(remote_nodes) > 0:
            node = random.choice(remote_nodes)
            url = urllib.parse.urljoin(f"{remote_url}/", f"{node}/")
            with closing(requests.post(url, headers=h)) as r:
                if r.status_code == 200:
                    if r.content.decode("utf-8").lower() == "true":
                        log.trace(f"uuidcode={startuuidcode} Active node: {node}")
                        return node
                    elif r.content.decode("utf-8").lower() == "false":
                        log.trace(
                            f"uuidcode={startuuidcode} Remove inactive node: {node}"
                        )
                        remote_nodes.remove(node)
                else:
                    rsc = r.status_code
                    log.error(
                        f"uuidcode={startuuidcode} {url} returned status_code {rsc}. Bugfix in tunneling service required."
                    )
                    return False
        return False

    def get_start_sh(self):
        startuuidcode = self.startuuidcode
        start_sh = os.path.join(
            self.service_base_path, "start_{system}.sh".format(system=self.system)
        )
        account_start_sh = os.path.join(
            self.service_base_path,
            "start_{system}_{account}.sh".format(
                system=self.system, account=self.account
            ),
        )
        project_start_sh = os.path.join(
            self.service_base_path,
            "start_{system}_{project}.sh".format(
                system=self.system, project=self.project
            ),
        )
        if os.path.exists(account_start_sh):
            log.debug(
                f"uuidcode={startuuidcode} Use account specific start_sh file {account_start_sh}"
            )
            with open(account_start_sh, "r") as f:
                data = f.read()
        elif os.path.exists(project_start_sh):
            log.debug(
                f"uuidcode={startuuidcode} Use project specific start_sh file {project_start_sh}"
            )
            with open(project_start_sh, "r") as f:
                data = f.read()
        else:
            log.debug(f"uuidcode={startuuidcode} Use default start_sh file {start_sh}")
            with open(start_sh, "r") as f:
                data = f.read()
        data = data.replace("{{PORT}}", str(self.port))
        data = data.replace("{{PROJECT}}", self.project)

        project_kernel = self.project in self.unicore_config.get(self.system, {}).get(
            "project_kernel", []
        )
        project_symlink = self.project in self.unicore_config.get(self.system, {}).get(
            "project_symlink", []
        )

        log.debug(
            f"uuidcode={startuuidcode} start_sh replace parameters: project_kernel={project_kernel} , project_symlink={project_symlink}"
        )
        data = data.replace("{{PROJECTKERNEL}}", "1" if project_kernel else "0")
        data = data.replace("{{PROJECTSYMLINK}}", "1" if project_symlink else "0")

        remotehubport = os.environ.get("REMOTEHUBPORT", "25488")
        data = data.replace("{{REMOTENODE}}", self.remote_node)
        data = data.replace("{{REMOTEHUBPORT}}", remotehubport)
        data = data.replace("{{STARTUUIDCODE}}", startuuidcode)
        data = data.replace("{{SERVERNAMESHORT}}", self.servername_short)
        data = data.replace("{{USERNAME}}", self.username)

        return data

    def get_prestart_sh(self):
        startuuidcode = self.startuuidcode
        prestart_sh = os.path.join(
            self.service_base_path, "pre_start_{system}.sh".format(system=self.system)
        )
        account_prestart_sh = os.path.join(
            self.service_base_path,
            "pre_start_{system}_{account}.sh".format(
                system=self.system, account=self.account
            ),
        )
        project_prestart_sh = os.path.join(
            self.service_base_path,
            "pre_start_{system}_{project}.sh".format(
                system=self.system, project=self.project
            ),
        )
        if os.path.exists(account_prestart_sh):
            log.debug(
                f"uuidcode={startuuidcode} Use account specific pre_start_sh file {account_prestart_sh}"
            )
            with open(account_prestart_sh, "r") as f:
                data = f.read()
        elif os.path.exists(project_prestart_sh):
            log.debug(
                f"uuidcode={startuuidcode} Use project specific pre_start_sh file {project_prestart_sh}"
            )
            with open(project_prestart_sh, "r") as f:
                data = f.read()
        else:
            log.debug(
                f"uuidcode={startuuidcode} Use default start_sh file {prestart_sh}"
            )
            with open(prestart_sh, "r") as f:
                data = f.read()
        return data

    def get_config_py(self):
        config_py = os.path.join(
            self.service_base_path, "config_{system}.py".format(system=self.system)
        )
        with open(config_py, "r") as f:
            data = f.read()

        remotehubport = os.environ.get("REMOTEHUBPORT", "25488")
        log.debug(
            "uuidcode={uuidcode} config_py replace parameters: remote_node={remote_node} , remotehubport={remotehubport} , username={username} , servername_short={servername_short} ".format(
                uuidcode=self.startuuidcode,
                remote_node=self.remote_node,
                remotehubport=remotehubport,
                username=self.username,
                servername_short=self.servername_short,
            )
        )
        data = data.replace("{{REMOTENODE}}", self.remote_node)
        data = data.replace("{{REMOTEHUBPORT}}", remotehubport)
        data = data.replace("{{USERNAME}}", self.username)
        data = data.replace("{{SERVERNAME_SHORT}}", self.servername_short)
        return data

    def get_inline_imports(self):
        startuuidcode = self.startuuidcode
        remote_nodes = self.unicore_config.get(self.system, {}).get("nodes", [])
        try:
            self.remote_node = self.get_active_remote_node(remote_nodes)
            if not self.remote_node:
                raise Exception(
                    f"uuidcode={startuuidcode} - Could not find remote node"
                )
        except:
            msg = "Couldn't find any active LoginNodes on {system}. Tested nodes: {remote_nodes}.".format(
                system=self.system, remote_nodes=", ".join(remote_nodes)
            )
            raise Exception(msg)

        self.remote_node = (
            self.unicore_config.get(self.system, {})
            .get("node_mapping", {})
            .get(self.remote_node, self.remote_node)
        )

        start_sh = self.get_start_sh()

        prestart_sh = self.get_prestart_sh()

        config_py = self.get_config_py()

        list = [
            {"From": "inline://dummy", "To": ".start.sh", "Data": start_sh},
            {"From": "inline://dummy", "To": ".pre_start.sh", "Data": prestart_sh},
            {"From": "inline://dummy", "To": ".config.py", "Data": config_py},
            {
                "From": "inline://dummy",
                "To": ".jupyter.token",
                "Data": self.env["JUPYTERHUB_API_TOKEN"],
            },
        ]
        return list

    def get_notification_url(self):
        jupyterhub_notification_url = os.environ.get("JUPYTERHUB_NOTIFICATION_URL", "")
        if not jupyterhub_notification_url:
            return ""
        if jupyterhub_notification_url[-1] == "/":
            jupyterhub_notification_url = jupyterhub_notification_url[:-1]
        url = "/".join(
            [
                f"{jupyterhub_notification_url}/",
                "{username}/".format(username=self.username),
                "{}_{}_{}/".format(
                    len(self.startuuidcode), self.startuuidcode, self.servername_short
                ),
            ]
        )
        return url

    def get_resources(self):
        if self.partition == "LoginNode":
            return False
        resources = os.environ.get("RESOURCES", "").split(" ")
        ret = {}
        for resource in resources:
            if f"resource_{resource}" in self.user_options:
                ret[resource] = self.user_options[f"resource_{resource}"]
        if "reservation_input" in self.user_options:
            ret["Reservation"] = self.user_options["reservation_input"]
        if self.unicore_config.get(self.system, {}).get(
            "queue_in_job_description", False
        ):
            ret["Queue"] = self.partition
        return ret

    def create_job_description(self):
        # create job_description dependencies
        inline_imports = self.get_inline_imports()

        # create job description
        self.job_description = {
            "ApplicationName": "Bash shell",
            "Executable": "/bin/bash",
            "Arguments": [".start.sh"],
            "Environment": self.env,
            "Imports": inline_imports,
        }

        notification_url = self.get_notification_url()
        if notification_url:
            self.job_description["Notification"] = notification_url

        if self.partition in ["LoginNode", "LoginNodeVis"]:
            self.job_description["Job type"] = "INTERACTIVE"
            nodes = self.unicore_config.get(self.system, {}).get(self.partition, [])
            if len(nodes) > 0:
                node = random.choice(nodes)
                self.job_description["Login node"] = node

        resources = self.get_resources()
        if resources:
            self.job_description["Resources"] = resources

        if self.unicore_config.get(self.system, {}).get("strict_session_ids", False):
            self.job_description["Environment"][
                "JUPYTERHUB_SESSION_ID_REQUIRED"
            ] = "true"
        if self.unicore_config.get(self.system, {}).get(
            "strict_session_ids_user", False
        ):
            self.job_description["Environment"][
                "JUPYTERHUB_SESSION_ID_REQUIRED_USER"
            ] = "true"

    def is_slurm(self):
        return self.system in os.environ.get("SLURMSYSTEMS").split()

    def is_docker(self):
        return self.system in os.environ.get("DOCKERSYSTEMS").split()

    def jupyterhub_status_update(self):
        status_url = self.env.get("JUPYTERHUB_STATUS_URL", "")
        hub_api_url = os.environ.get("JUPYTERHUB_API_URL", "")
        post_start_update_no = os.environ.get("JUPYTERHUB_POST_START_UPDATE_NO", "1")
        if not status_url:
            log.error(
                "No status_url in environment. Cannot update JupyterHub spawn status"
            )
            return
        if not hub_api_url:
            log.error(
                "No hub_api_url in environment. Cannot update JupyterHub spawn status"
            )
            return
        if status_url[-1] == "/":
            status_url = status_url[:-1]
        if hub_api_url[-1] == "/":
            hub_api_url = hub_api_url[:-1]
        log.debug(f"Status url: {status_url}")
        log.debug(f"hub intern url: {hub_api_url}")
        h = {
            "Host": os.environ.get("REQUEST_HEADER_HOST"),
            "uuidcode": self.startuuidcode,
            "Authorization": "token {}".format(self.env["JUPYTERHUB_API_TOKEN"]),
        }
        url = "/".join([hub_api_url, status_url, post_start_update_no])
        with closing(requests.post(url, headers=h)) as r:
            if r.status_code != 204:
                log.warning(
                    "Status update sent unexpected status code: {}".format(
                        r.status_code
                    )
                )
                log.warning(r.content.decode("utf-8"))

    def start(self):
        if self.is_slurm():
            self.create_job_description()
            transport = self.pyunicore_transport(set_preferences=True)
            base_url = self.pyunicore_base_url(transport)
            job = self.pyunicore_job(transport, base_url)
            self.resource_url = job.resource_url
            self.jupyterhub_status_update()
        elif self.is_docker():
            userlab_url = os.environ.get("USERLAB_URL")
            url = "/".join(
                [
                    userlab_url,
                    str(self.id),
                    "default",
                    self.username,
                    self.dockerimage,
                    str(self.port),
                ]
            )

            h = {"uuidcode": self.startuuidcode}
            data = {
                "JUPYTERHUB_API_TOKEN": self.env.get("JUPYTERHUB_API_TOKEN", ""),
                "JUPYTERHUB_API_URL": os.environ.get("JUPYTERHUB_API_URL", ""),
                "JUPYTERHUB_CLIENT_ID": self.env.get("JUPYTERHUB_CLIENT_ID", ""),
                "JUPYTERHUB_USER": self.env.get("JUPYTERHUB_USER", ""),
                "JUPYTERHUB_SERVICE_PREFIX": self.env.get("JUPYTERHUB", ""),
                "JUPYTERHUB_BASE_URL": self.env.get("JUPYTERHUB_BASE_URL", ""),
                "JUPYTERHUB_STATUS_URL": self.env.get("JUPYTERHUB_STATUS_URL", ""),
                "JUPYTERHUB_CANCEL_URL": self.env.get("JUPYTERHUB_CANCEL_URL", ""),
            }
            with closing(requests.post(url, headers=h, json=data, verify=False)) as r:
                log.debug(
                    "uuidcode={uuidcode} - \nStatus Code: {status_code} - \nOut: {text}".format(
                        uuidcode=self.startuuidcode,
                        status_code=r.status_code,
                        text=r.text,
                    )
                )
            self.jupyterhub_status_update()
        else:
            raise NotImplementedError("System {} not supported".format(self.system))

    def status(self, uuidcode, access_token=None, set_preferences=False):
        if self.is_slurm():
            if self.resource_url is None:
                return False
            transport = self.pyunicore_transport(
                access_token=access_token, set_preferences=set_preferences
            )
            job = unicore_client.Job(transport, self.resource_url)
            return job.is_running()
        elif self.is_docker():
            userlab_url = os.environ.get("USERLAB_URL")
            url = "/".join([userlab_url, str(self.id)])
            h = {"uuidcode": uuidcode}
            with closing(requests.get(url, headers=h, verify=False)) as r:
                log.debug(
                    "uuidcode={uuidcode} - \nStatus Code: {status_code} - \nOut: {text}".format(
                        uuidcode=uuidcode, status_code=r.status_code, text=r.text
                    )
                )
                if r.status_code == 200:
                    if r.text.lower() == "true":
                        return True
                return False
        else:
            raise NotImplementedError("System {} not supported".format(self.system))

    def stop(self, uuidcode, access_token=None, set_preferences=False):
        if self.is_slurm():
            transport = self.pyunicore_transport(
                access_token=access_token, set_preferences=set_preferences
            )
            job = unicore_client.Job(transport, self.resource_url)
            job.abort()
            wd = job.working_dir
            job_base_dir = os.environ.get("JOBBASEDIR")
            timestamp = datetime.fromtimestamp(time.time()).strftime(
                "%Y_%m_%d-%H:%M:%S.%s"
            )
            timestamp_id = "{}-{}".format(timestamp, str(job.job_id))
            dst_dir = os.path.join(job_base_dir, self.servername, timestamp_id)
            Path(dst_dir).mkdir(parents=True, exist_ok=True)
            try:
                copy_all = self.copy(wd.listdir(), dst_dir)
                # If we could not copy a file we don't delete the JobDir
                if copy_all and os.environ.get(
                    "DELETE_UNICORE_JOBDIRS", "0"
                ).lower() in ("true", "1"):
                    job.delete()
            except:
                log.exception(f"Could not copy files from Job to {dst_dir}")
        elif self.is_docker():
            userlab_url = os.environ.get("USERLAB_URL")
            url = "/".join([userlab_url, str(self.id)])
            h = {"uuidcode": uuidcode}
            with closing(requests.delete(url, headers=h, verify=False)) as r:
                log.debug(
                    "uuidcode={uuidcode} - \nStatus Code: {status_code} - \nOut: {text}".format(
                        uuidcode=uuidcode, status_code=r.status_code, text=r.text
                    )
                )
        else:
            raise NotImplementedError("System {} not supported".format(self.system))
        self.stop_tunnel(uuidcode)

    def stop_tunnel(self, uuidcode):
        tunnel_url = os.environ.get("TUNNEL_URL")
        if tunnel_url and tunnel_url[-1] == "/":
            tunnel_url = tunnel_url[:-1]
        url = "/".join([tunnel_url, self.servername])
        headers = {"uuidcode": uuidcode, "Host": os.environ.get("REQUEST_HEADER_HOST")}
        log.debug(f"call {url} with {headers}")
        with closing(requests.delete(url, headers=headers, verify=False)) as r:
            if r.status_code != 200:
                log.warning(r.status_code)
                log.warning(r.content.decode("utf-8"))

    def copy(self, path_dict, dst_dir):
        """ return True if anything was copied """
        ret = True
        for filename, pathfile in path_dict.items():
            if isinstance(pathfile, unicore_client.PathFile):
                dst = os.path.join(dst_dir, filename)
                log.debug(f"copy {pathfile} to {dst}")
                try:
                    pathfile.download(dst)
                except:
                    log.exception(f"Could not copy {pathfile}")
                    ret = False
            else:
                log.warning(
                    "Copy of {} {} not supported.".format(type(pathfile), pathfile)
                )
                ret = False
        return ret

    def pyunicore_transport(self, access_token=None, set_preferences=False):
        if not access_token:
            access_token = self.auth_state.get("access_token")
        unicore_cert = os.environ.get("UNICORE_CERT", False)
        transport = unicore_client.Transport(
            access_token, oidc=True, verify=unicore_cert
        )
        if set_preferences:
            transport.preferences = "uid:{account},group:{project}".format(
                account=self.account, project=self.project
            )
        return transport

    def pyunicore_base_url(self, transport=None):
        if "base_url" in self.unicore_config.get(self.system, {}):
            base_url = self.unicore_config.get(self.system, {})["base_url"]
        else:
            if not transport:
                raise Exception("Transport required")
            reg_url = self.unicore_config.get("Registry", {}).get("base_url")
            unicore_system = (
                self.unicore_config.get("Registry", {})
                .get("site_mapping", {})
                .get(self.system, self.system)
            )
            sites = unicore_client.get_sites(transport, reg_url)
            base_url = sites.get(unicore_system)
        return base_url

    def pyunicore_job(self, transport, base_url):
        client = unicore_client.Client(transport, base_url)
        job = client.new_job(self.job_description)
        return job
