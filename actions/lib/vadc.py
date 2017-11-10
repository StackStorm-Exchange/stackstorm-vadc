#!/usr/bin/python

import sys
import json
import time
from os import path
import yaml
import requests


class Vadc(object):

    DEBUG = False

    def __init__(self, host, user, passwd, logger):
        requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member
        if host.endswith('/') is False:
            host += "/"
        self.host = host
        self.user = user
        self.passwd = passwd
        self.logger = logger
        self.client = None
        self._cache = {}

    def _debug(self, message):
        if Vadc.DEBUG:
            self.logger.debug(message)

    def _get_api_version(self, apiRoot):
        url = self.host + apiRoot
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to locate API: {}, {}".format(res.status_code, res.text))
        versions = res.json()
        versions = versions["children"]
        major = max([int(ver["name"].split('.')[0]) for ver in versions])
        minor = max([int(ver["name"].split('.')[1]) for ver in versions if
                     ver["name"].startswith(str(major))])
        version = "{}.{}".format(major, minor)
        self._debug("API Version: {}".format(version))
        return version

    def _init_http(self):
        self.client = requests.Session()
        self.client.auth = (self.user, self.passwd)

    def _get_config(self, url, headers=None, params=None):
        self._debug("URL: " + url)
        try:
            self._init_http()
            response = self.client.get(url, verify=False, headers=headers, params=params)
        except:
            self.logger.error("Error: Unable to connect to API")
            raise Exception("Error: Unable to connect to API")
        self._debug("Status: {}".format(response.status_code))
        self._debug("Body: " + response.text)
        return response

    def _push_config(self, url, config, method="PUT", ct="application/json",
                     params=None, extra=None):
        self._debug("URL: " + url)
        try:
            self._init_http()
            if ct == "application/json":
                if extra is not None:
                    try:
                        if extra.startswith("{"):
                            extra = json.loads(extra, encoding="utf-8")
                        else:
                            extra = yaml.load(extra)
                        self._merge_extra(config, extra)
                    except Exception as e:
                        self.logger.warn("Failed to merge extra properties: {}".format(e))
                config = json.dumps(config)
            if method == "PUT":
                response = self.client.put(url, verify=False, data=config,
                                           headers={"Content-Type": ct}, params=params)
            else:
                response = self.client.post(url, verify=False, data=config,
                                            headers={"Content-Type": ct}, params=params)
        except requests.exceptions.ConnectionError:
            self.logger.error("Error: Unable to connect to API")
            raise Exception("Error: Unable to connect to API")

        self._debug("DATA: " + config)
        self._debug("Status: {}".format(response.status_code))
        self._debug("Body: " + response.text)
        return response

    def _del_config(self, url):
        self._debug("URL: " + url)
        try:
            self._init_http()
            response = self.client.delete(url, verify=False)
        except requests.exceptions.ConnectionError:
            sys.stderr.write("Error: Unable to connect to API {}".format(url))
            raise Exception("Error: Unable to connect to API")

        self._debug("Status: {}".format(response.status_code))
        self._debug("Body: " + response.text)
        return response

    def _upload_raw_binary(self, url, filename):
        if path.isfile(filename) is False:
            raise Exception("File: {} does not exist".format(filename))
        if path.getsize(filename) > 20480000:
            raise Exception("File: {} is too large.".format(filename))
        handle = open(filename, "rb")
        body = handle.read()
        handle.close()
        return self._push_config(url, body, ct="application/octet-stream")

    def _dictify(self, listing, keyName):
        dictionary = {}
        for item in listing:
            k = item.pop(keyName)
            dictionary[k] = item

    def _merge_extra(self, obj1, obj2):
        for section in obj2["properties"].keys():
            if section in obj1["properties"].keys():
                obj1["properties"][section].update(obj2["properties"][section])
            else:
                obj1["properties"][section] = obj2["properties"][section]

    def _cache_store(self, key, data, timeout=10):
        exp = time.time() + timeout
        self._debug("Cache Store: {}".format(key))
        self._cache[key] = {"exp": exp, "data": data}

    def _cache_lookup(self, key):
        now = time.time()
        if key in self._cache:
            entry = self._cache[key]
            if entry["exp"] > now:
                self._debug("Cache Hit: {}".format(key))
                return entry["data"]
        self._debug("Cache Miss: {}".format(key))
        return None

    def dump_cache(self):
        return json.dumps(self._cache, encoding="utf-8")

    def load_cache(self, cache):
        self._cache = json.loads(cache, encoding="utf-8")


class Bsd(Vadc):

    def __init__(self, config, logger):

        try:
            host = config['brcd_sd_host']
            user = config['brcd_sd_user']
            passwd = config['brcd_sd_pass']
        except KeyError:
            raise ValueError("brcd_sd_host, brcd_sd_user, and brcd_sd_pass must be configured")

        super(Bsd, self).__init__(host, user, passwd, logger)
        self.version = self._get_api_version("api/tmcm")
        self.baseUrl = host + "api/tmcm/" + self.version

    def _get_vtm_licenses(self):
        url = self.baseUrl + "/license"
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to get licenses: {}, {}".format(res.status_code, res.text))
        licenses = res.json()
        licenses = licenses["children"]
        universal = [int(lic["name"][11:]) for lic in licenses
                     if lic["name"].startswith("universal_v")]
        universal.sort(reverse=True)
        legacy = [float(lic["name"][7:]) for lic in licenses
                  if lic["name"].startswith("legacy_")]
        legacy.sort(reverse=True)
        order = []
        order += (["universal_v" + str(ver) for ver in universal])
        order += (["legacy_" + str(ver) for ver in legacy])
        return order

    def get_cluster_members(self, cluster):
        url = self.baseUrl + "/cluster/" + cluster
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to locate cluster: {}, {}".format(res.status_code, res.text))
        config = res.json()
        return config["members"]

    def get_active_vtm(self, vtms=None, cluster=None):
        if cluster is None and vtms is None:
            raise Exception("Error - You must supply either a list of vTMs or a Cluster ID")
        if cluster is not None and cluster != "":
            vtms = self.get_cluster_members(cluster)
        for vtm in vtms:
            url = self.baseUrl + "/instance/" + vtm + "/tm/"
            res = self._get_config(url)
            if res.status_code == 200:
                return vtm
        return None

    def add_vtm(self, vtm, password, address, bw, fp):
        url = self.baseUrl + "/instance/?managed=false"

        if address is None:
            address = vtm

        config = {"bandwidth": bw, "tag": vtm, "owner": "stanley", "stm_feature_pack": fp,
                  "rest_address": address + ":9070", "admin_username": "admin",
                  "rest_enabled": False, "host_name": address, "management_address": address}

        if password is not None:
            config["admin_password"] = password
            config["rest_enabled"] = True

            # Try each of our available licenses.
            licenses = self._get_vtm_licenses()
            for license in licenses:
                config["license_name"] = license
                res = self._push_config(url, config, "POST")
                if res.status_code == 201:
                    break
        else:
            res = self._push_config(url, config, "POST")

        if res.status_code != 201:
            raise Exception("Failed to add vTM. Response: {}, {}".format(res.status_code, res.text))
        return res.json()

    def del_vtm(self, vtm):
        url = self.baseUrl + "/instance/" + vtm
        config = {"status": "deleted"}
        res = self._push_config(url, config, "POST")
        if res.status_code != 200:
            raise Exception("Failed to del vTM. Response: {}, {}".format(res.status_code, res.text))
        return res.json()

    def get_vtm(self, tag):
        vtm = self._cache_lookup("get_vtm_" + tag)
        if vtm is None:
            url = self.baseUrl + "/instance/" + tag
            res = self._get_config(url)
            if res.status_code != 200:
                raise Exception("Failed to get vTM {}. Response: {}, {}".format(
                    vtm, res.status_code, res.text))
            vtm = res.json()
            self._cache_store("get_vtm_" + tag, vtm)
        return vtm

    def list_vtms(self, full, deleted, stringify):
        instances = self._cache_lookup("list_vtms")
        if instances is None:
            url = self.baseUrl + "/instance/"
            res = self._get_config(url)
            if res.status_code != 200:
                raise Exception("Failed to list vTMs. Response: {}, {}".format(
                    res.status_code, res.text))
            instances = res.json()
            self._cache_store("list_vtms", instances)

        output = []
        for instance in instances["children"]:
            config = self.get_vtm(instance["name"])
            if deleted is False and config["status"] == "Deleted":
                continue
            if full:
                config["name"] = instance["name"]
                output.append(config)
            else:
                out_dict = {k: config[k] for k in ("host_name", "tag", "status",
                                                   "stm_feature_pack", "bandwidth")}
                out_dict["name"] = instance["name"]
                output.append(out_dict)

        if stringify:
            return json.dumps(output, encoding="utf-8")
        else:
            return output

    def get_status(self, vtm=None, stringify=False):
        instances = self._cache_lookup("get_status")
        if instances is None:
            url = self.baseUrl + "/monitoring/instance"
            res = self._get_config(url)
            if res.status_code != 200:
                raise Exception("Failed get Status. Result: {}, {}".format(
                    res.status_code, res.text))

            instances = res.json()
            self._cache_store("get_status", instances)

        if vtm is not None:
            for instance in instances:
                if instance["tag"] != vtm and instance["name"] != vtm:
                    instances.remove(instance)

        if stringify:
            return json.dumps(instances, encoding="utf-8")
        else:
            return instances

    def get_errors(self, stringify=False):
        instances = self.get_status()
        errors = {}
        for instance in instances:
            error = {}
            self._debug(instance)
            if instance["id_health"]["alert_level"] != 1:
                error["id_health"] = instance["id_health"]
            if instance["rest_access"]["alert_level"] != 1:
                error["rest_access"] = instance["rest_access"]
            if instance["licensing_activity"]["alert_level"] != 1:
                error["licensing_activity"] = instance["licensing_activity"]
            if instance["traffic_health"]["error_level"] != "ok":
                error["traffic_health"] = instance["traffic_health"]
            if len(error) != 0:
                error["tag"] = instance["tag"]
                error["name"] = instance["name"]
                if "traffic_health" in error:
                    if "virtual_servers" in error["traffic_health"]:
                        del error["traffic_health"]["virtual_servers"]
                errors[instance["name"]] = error

        if stringify:
            return json.dumps(errors, encoding="utf-8")
        else:
            return errors

    def get_monitor_intervals(self, setting=None):
        intervals = self._cache_lookup("get_monitor_intervals")
        if intervals is None:
            url = self.baseUrl + "/settings/monitoring"
            res = self._get_config(url)
            if res.status_code != 200:
                raise Exception("Failed to get Monitoring Intervals. Result: {}, {}".format(
                    res.status_code, res.text))

            intervals = res.json()
            self._cache_store("get_monitor_intervals", intervals)

        if setting is not None:
            if setting not in intervals:
                raise Exception("Setting: {} does not exist.".format(setting))
            return intervals[setting]
        return intervals

    def get_bandwidth(self, vtm=None, stringify=False):
        instances = self.get_status(vtm)
        bandwidth = {}
        for instance in instances:
            config = self.get_vtm(instance["name"])
            tag = config["tag"]
            # Bytes/Second
            if "throughput_out" in instance:
                current = (instance["throughput_out"] / 1000000.0) * 8
            else:
                current = 0.0
            # Mbps
            assigned = config["bandwidth"]
            # Bytes/Second
            if "metrics_peak_throughput" in config:
                peak = (config["metrics_peak_throughput"] / 1000000.0) * 8
            else:
                peak = 0.0
            bandwidth[instance["name"]] = {"tag": tag, "current": current,
                                           "assigned": assigned, "peak": peak}

        if stringify:
            return json.dumps(bandwidth, encoding="utf-8")
        else:
            return bandwidth

    def set_bandwidth(self, vtm, bw):
        url = self.baseUrl + "/instance/" + vtm
        config = {"bandwidth": bw}
        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to set Bandwidth. Result: {}, {}".format(
                res.status_code, res.text))
        config = res.json()
        return config


class Vtm(Vadc):

    def __init__(self, config, logger, vtm):

        try:
            self._proxy = config['brcd_sd_proxy']
            if self._proxy:
                host = config['brcd_sd_host']
                user = config['brcd_sd_user']
                passwd = config['brcd_sd_pass']
            else:
                host = config['brcd_vtm_host']
                user = config['brcd_vtm_user']
                passwd = config['brcd_vtm_pass']
        except KeyError:
            raise ValueError("You must set key brcd_sd_proxy, and either " +
                             "brcd_sd_[host|user|pass] or brcd_vtm_[host|user|pass].")

        self.vtm = vtm
        self.bsdVersion = None
        super(Vtm, self).__init__(host, user, passwd, logger)
        if self._proxy:
            self.bsdVersion = self._get_api_version("api/tmcm")
            self.version = self._get_api_version(
                "api/tmcm/{}/instance/{}/tm".format(self.bsdVersion, vtm))
            self.baseUrl = host + "api/tmcm/{}".format(self.bsdVersion) + \
                "/instance/{}/tm/{}".format(vtm, self.version)
        else:
            self.version = self._get_api_version("api/tm")
            self.baseUrl = host + "api/tm/{}".format(self.version)
        self.configUrl = self.baseUrl + "/config/active"
        self.statusUrl = self.baseUrl + "/status/local_tm"

    def _get_node_table(self, name):
        url = self.configUrl + "/pools/" + name
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to get pool. Result: {}, {}".format(res.status_code, res.text))

        config = res.json()
        return config["properties"]["basic"]["nodes_table"]

    def _get_vs_config(self, name):
        url = self.configUrl + "/virtual_servers/" + name
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to get VS. Result: {}, {}".format(res.status_code, res.text))

        config = res.json()
        return config

    def _set_vs_config(self, name, config):
        url = self.configUrl + "/virtual_servers/" + name
        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to set VS. Result: {}, {}".format(res.status_code, res.text))
        return res

    def _get_vs_rules(self, name):
        config = self._get_vs_config(name)
        rules = {k: config["properties"]["basic"][k] for k in
                 ("request_rules", "response_rules", "completionrules")}
        return rules

    def _set_vs_rules(self, name, rules):
        config = {"properties": {"basic": rules}}
        res = self._set_vs_config(name, config)
        if res.status_code != 200:
            raise Exception("Failed set VS Rules. Result: {}, {}".format(res.status_code, res.text))

    def insert_rule(self, vsname, rulename, insert=True):
        rules = self._get_vs_rules(vsname)
        if insert:
            if rulename in rules["request_rules"]:
                raise Exception("VServer {} already in maintenance".format(vsname))
            rules["request_rules"].insert(0, rulename)
        else:
            if rulename not in rules["request_rules"]:
                raise Exception("VServer {} is not in maintenance".format(vsname))
            rules["request_rules"].remove(rulename)
        self._set_vs_rules(vsname, rules)

    def enable_maintenance(self, vsname, rulename="maintenance", enable=True):
        self.insert_rule(vsname, rulename, enable)

    def get_pool_nodes(self, name):
        nodeTable = self._get_node_table(name)
        nodes = {"active": [], "disabled": [], "draining": []}
        for node in nodeTable:
            if node["state"] == "active":
                nodes["active"].append(node["node"])
            elif node["state"] == "disabled":
                nodes["disabled"].append(node["node"])
            elif node["state"] == "draining":
                nodes["draining"].append(node["node"])
            else:
                self.logger.warn("Unknown Node State: {}".format(node["state"]))

        return nodes

    def set_pool_nodes(self, name, active, draining, disabled):
        url = self.configUrl + "/pools/" + name
        nodeTable = []
        if active is not None and active:
            nodeTable.extend([{"node": node, "state": "active"} for node in active])
        if draining is not None and draining:
            nodeTable.extend([{"node": node, "state": "draining"} for node in draining])
        if disabled is not None and disabled:
            nodeTable.extend([{"node": node, "state": "disabled"} for node in disabled])
        config = {"properties": {"basic": {"nodes_table": nodeTable}}}
        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to set nodes. Result: {}, {}".format(res.status_code, res.text))

    def drain_nodes(self, name, nodes, drain=True):
        url = self.configUrl + "/pools/" + name
        nodeTable = self._get_node_table(name)
        for entry in nodeTable:
            if entry["node"] in nodes:
                if drain:
                    entry["state"] = "draining"
                else:
                    entry["state"] = "active"

        config = {"properties": {"basic": {"nodes_table": nodeTable}}}
        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add pool. Result: {}, {}".format(res.status_code, res.text))

    def add_pool(self, name, nodes, algorithm, persistence, monitors, extra=None):
        url = self.configUrl + "/pools/" + name

        nodeTable = []
        for node in nodes:
            nodeTable.append({"node": node, "state": "active"})

        config = {"properties": {"basic": {"nodes_table": nodeTable}, "load_balancing": {}}}

        if monitors is not None:
            config["properties"]["basic"]["monitors"] = monitors

        if persistence is not None:
            config["properties"]["basic"]["persistence_class"] = persistence

        if algorithm is not None:
            config["properties"]["load_balancing"]["algorithm"] = algorithm

        res = self._push_config(url, config, extra=extra)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add pool. Result: {}, {}".format(res.status_code, res.text))

    def del_pool(self, name):
        url = self.configUrl + "/pools/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to del pool. Result: {}, {}".format(res.status_code, res.text))

    def add_vserver(self, name, pool, tip, port, protocol, extra=None):
        url = self.configUrl + "/virtual_servers/" + name
        config = {"properties": {"basic": {"pool": pool, "port": port, "protocol": protocol,
                                           "listen_on_any": False, "listen_on_traffic_ips": [tip],
                                           "enabled": True}}}

        res = self._push_config(url, config, extra=extra)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add VS. Result: {}, {}".format(res.status_code, res.text))

    def del_vserver(self, name):
        url = self.configUrl + "/virtual_servers/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to del VS. Result: {}, {}".format(res.status_code, res.text))

    def add_tip(self, name, vtms, addresses, extra=None):
        url = self.configUrl + "/traffic_ip_groups/" + name

        config = {"properties": {"basic": {"ipaddresses": addresses,
                                           "machines": vtms, "enabled": True}}}

        res = self._push_config(url, config, extra=extra)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add TIP. Result: {}, {}".format(res.status_code, res.text))

    def del_tip(self, name):
        url = self.configUrl + "/traffic_ip_groups/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to del TIP. Result: {}, {}".format(res.status_code, res.text))

    def add_server_cert(self, name, public, private):
        url = self.configUrl + "/ssl/server_keys/" + name

        public = public.replace("\\n", "\n")
        private = private.replace("\\n", "\n")

        config = {"properties": {"basic": {"public": public, "private": private}}}

        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add Server Certificate." +
                            " Result: {}, {}".format(res.status_code, res.text))

    def del_server_cert(self, name):
        url = self.configUrl + "/ssl/server_keys/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to delete Server Certificate." +
                            " Result: {}, {}".format(res.status_code, res.text))

    def enable_ssl_offload(self, name, cert="", on=True, xproto=False, headers=False):
        url = self.configUrl + "/virtual_servers/" + name
        config = {"properties": {"basic": {"ssl_decrypt": on, "add_x_forwarded_proto": xproto},
                                 "ssl": {"add_http_headers": headers, "server_cert_default": cert}}}

        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to configure SSl Offload on {}.".format(name) +
                            " Result: {}, {}".format(res.status_code, res.text))

    def enable_ssl_encryption(self, name, on=True, verify=False):
        url = self.configUrl + "/pools/" + name
        config = {"properties": {"ssl": {"enable": on, "strict_verify": verify}}}

        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to configure SSl Encryption on {}.".format(name) +
                            " Result: {}, {}".format(res.status_code, res.text))

    def add_session_persistence(self, name, method, cookie=None):
        types = ["ip", "universal", "named", "transparent", "cookie", "j2ee", "asp", "ssl"]
        if method not in types:
            raise Exception("Failed to add SP Class. Invalid method: {}".format(method) +
                            "Must be one of: {}".format(types))
        if method == "cookie" and cookie is None:
            raise Exception("Failed to add SP Class. You must provide a cookie name.")

        if cookie is None:
            cookie = ""

        url = self.configUrl + "/persistence/" + name
        config = {"properties": {"basic": {"type": method, "cookie": cookie}}}

        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to add Session Persistence Class" +
                            " Result: {}, {}".format(res.status_code, res.text))

    def del_session_persistence(self, name):
        url = self.configUrl + "/persistence/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to delete Session Persistence Class." +
                            " Result: {}, {}".format(res.status_code, res.text))

    def list_backups(self):
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full"
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to get Backup Listing." +
                            " Result: {}, {}".format(res.status_code, res.text))
        listing = res.json()["children"]
        output = {}
        for backup in [backup["name"] for backup in listing]:
            url = self.statusUrl + "/backups/full/" + backup
            res = self._get_config(url)
            if res.status_code == 200:
                out = res.json()
                output[backup] = out["properties"]["backup"]
        return output

    def create_backup(self, name, description):
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full/" + name
        description = "" if description is None else description
        config = {"properties": {"backup": {"description": description}}}
        res = self._push_config(url, config)
        if res.status_code != 201 and res.status_code != 200:
            raise Exception("Failed to create Backup." +
                            " Result: {}, {}".format(res.status_code, res.text))

    def restore_backup(self, name):
        if self._proxy and self.bsdVersion < 2.4:
            raise Exception("Backup restoration requires BSD Version 2.6 when proxying.")
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full/" + name + "?restore"
        config = {"properties": {}}
        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to create Backup." +
                            " Result: {}, {}".format(res.status_code, res.text))
        return res.json()

    def delete_backup(self, name):
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full/" + name
        res = self._del_config(url)
        if res.status_code != 204:
            raise Exception("Failed to delete Backup." +
                            " Result: {}, {}".format(res.status_code, res.text))

    def get_backup(self, name):
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full/" + name
        headers = {"Accept": "application/x-tar"}
        res = self._get_config(url, headers=headers)
        if res.status_code != 200:
            raise Exception("Failed to download Backup." +
                            " Result: {}, {}".format(res.status_code, res.text))
        backup = res.content
        return backup

    def upload_backup(self, backup):
        if self.version < 3.9:
            raise Exception("Backups require vTM 11.0 or newer")
        url = self.statusUrl + "/backups/full/"
        res = self._push_config(url, backup, method="POST", ct="application/x-tar")
        if res.status_code != 201 and res.status_code != 204:
            raise Exception("Failed to upload Backup." +
                            "Result: {}, {}".format(res.status_code, res.text))

    def upload_action_program(self, name, filename):
        url = self.configUrl + "/action_programs/" + name
        res = self._upload_raw_binary(url, filename)
        if res.status_code != 201 and res.status_code != 204:
            raise Exception("Failed to upload program." +
                            " Result: {}, {}".format(res.status_code, res.text))

    def add_action_program(self, name, program, arguments):
        config = {"properties": {"basic": {"type": "program"}, "program":
                                 {"arguments": arguments, "program": program}}}
        url = self.configUrl + "/actions/" + name
        res = self._push_config(url, config)
        if res.status_code != 200 and res.status_code != 201:
            raise Exception("Failed to add action." +
                            " Result: {}, {}".format(res.status_code, res.text))

    def get_event_type(self, name):
        url = self.configUrl + "/event_types/" + name
        res = self._get_config(url)
        if res.status_code == 404:
            return None
        elif res.status_code != 200:
            raise Exception("Failed to get event." +
                            " Result: {}, {}".format(res.status_code, res.text))
        return res.json()

    def add_event_type_action(self, event, action):
        url = self.configUrl + "/event_types/" + event
        config = self.get_event_type(event)
        if config is None:
            return False
        entries = config["properties"]["basic"]["actions"]
        if action in entries:
            return True
        entries.append(action)
        res = self._push_config(url, config)
        if res.status_code != 200:
            raise Exception("Failed to Set Action: {}".format(action) +
                            " for Event: {}.".format(event) +
                            " Result: {}, {}".format(res.status_code, res.text))
