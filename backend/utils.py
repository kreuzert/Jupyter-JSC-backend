import copy
import json
import logging
import os
from contextlib import closing
from subprocess import check_output
from subprocess import STDOUT

import requests

# Get an instance of a logger
log = logging.getLogger("Backend")


def update_resources():
    factories_path = os.environ.get(
        "FACTORIES_PATH", "factories/default_target_system_factory"
    )
    base_resources_path = os.environ.get("BASE_RESOURCES_PATH", "")
    full_resources_path = os.environ.get("FULL_RESOURCES_PATH", "")
    unicore_json_path = os.environ.get("UNICORE_CONFIG_PATH", "")

    with open(full_resources_path, "r") as f:
        old_resources = json.load(f)
    with open(base_resources_path, "r") as f:
        base_resources = json.load(f)
    with open(unicore_json_path, "r") as f:
        unicore_json = json.load(f)

    full_resources = {}
    headers = {"Accept": "application/json"}

    for system, partitions in base_resources.items():
        full_resources[system] = {}
        res = {}
        if system in unicore_json.keys() and "base_url" in unicore_json[system].keys():
            base_url = unicore_json[system]["base_url"]
            try:
                with closing(
                    requests.get(
                        "{}/{}".format(base_url, factories_path),
                        headers=headers,
                        verify=False,
                    )
                ) as r:
                    if r.status_code == 200:
                        res = r.json()["resources"]
                    else:
                        log.error(
                            "Could not receive resources for {} - {} {}".format(
                                system, r.status_code, r.text.decode("utf-8")
                            )
                        )
            except:
                log.exception("Could not receive resources for {}".format(system))
        else:
            log.error(
                "Could not receive resources for {} - No base_url in {}".format(
                    system, unicore_json_path
                )
            )

        for partition, resources in partitions.items():
            full_resources[system][partition] = {}
            if not resources:
                # LoginNodes, do nothing
                continue
            if partition not in res.keys():
                # Use backup values instead
                full_resources[system][partition] = copy.deepcopy(resources)
                continue
            for resource, key_value in resources.items():
                full_resources[system][partition][resource] = copy.deepcopy(key_value)
                _min_max = res[partition].get(resource, None)
                if _min_max and type(_min_max) == str and "-" in _min_max:
                    min_max = [int(s) for s in _min_max.split("-")]
                else:
                    min_max = copy.deepcopy(key_value["MINMAX"])
                full_resources[system][partition][resource]["MINMAX"] = min_max
                full_resources[system][partition][resource]["TEXT"] = (
                    key_value["TEXT"]
                    .replace("_min_", str(min_max[0]))
                    .replace("_max_", str(min_max[1]))
                )
                full_resources[system][partition][resource]["DEFAULT"] = int(
                    str(key_value["DEFAULT"])
                    .replace("_min_", str(min_max[0]))
                    .replace("_max_", str(min_max[1]))
                )
    output = {
        "refresh_call_at": old_resources["refresh_call_at"],
        "value": full_resources,
    }
    with open(full_resources_path, "w") as f:
        json.dump(output, f, indent=4, sort_keys=True)


def update_reservations():
    reservation_key = os.environ.get("RESERVATIONS_SSH_KEY")
    reservation_timeout = int(os.environ.get("RESERVATIONS_SSH_TIMEOUT", "3"))
    reservations_json_path = os.environ.get("RESERVATIONS_PATH", "")
    unicore_json_path = os.environ.get("UNICORE_CONFIG_PATH", "")

    with open(reservations_json_path, "r") as f:
        old_reservations = json.load(f)
    with open(unicore_json_path, "r") as f:
        unicore_json = json.load(f)

    ret = {"refresh_call_at": old_reservations["refresh_call_at"], "value": {}}

    def no_null(x):
        if x == "(null)":
            return ""
        return x

    for system in unicore_json.get("reservation_systems", []):
        fuser = unicore_json[system]["fuser"]
        host = unicore_json[system]["host"]
        li = [
            "ssh",
            "-i",
            reservation_key,
            "-oLogLevel=ERROR",
            "-oStrictHostKeyChecking=no",
            "-oUserKnownHostsFile=/dev/null",
            f"{fuser}@{host}",
            "-T",
        ]
        log.debug("Cmd: {}".format(" ".join(li)))
        output = (
            check_output(li, stderr=STDOUT, timeout=reservation_timeout)
            .decode("utf8")
            .rstrip()
        )
        log.debug("output: {}".format(output))
        if output == "No reservations in the system":
            ret["value"][system] = []
            continue
        split_string = "ReservationName="
        reservation_list = [
            "{}{}".format(split_string, x).split()
            for x in output.strip().split(split_string)
            if x
        ]
        csv = [
            ";".join([no_null(y.split("=", 1)[1]) for y in x if y])
            for x in reservation_list
        ]
        ret["value"][system] = csv
    with open(reservations_json_path, "w") as f:
        json.dump(ret, f, indent=4, sort_keys=True)
