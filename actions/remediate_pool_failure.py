#! /usr/bin/python

import json
from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm
from lib.vadc import Bsd


class RemediatePoolFailure(Action):

    def run(self, errors, error_level):

        errors = json.loads(errors, encoding="utf-8")
        if "name" not in errors:
            raise Exception("Error: Instance name not provided in errors. Can not continue!")

        instance = errors["name"]
        vtm = Vtm(self.config, self.logger, instance)
        bsd = Bsd(self.config, self.logger)
        status = bsd.get_status(instance)[0]

        nodes = errors["traffic_health"]["failed_nodes"]
        failedPools = {pool: [node["node"] for node in nodes for pool in node["pools"]]
            for node in nodes for pool in node["pools"]}

        for pool in failedPools.keys():
            nodes = vtm.get_pool_nodes(pool)
            if set(nodes["active"]).issubset(failedPools[pool]):
                self.logger.debug("Pool Dead")
                for vs in status["traffic_health"]["virtual_servers"]:
                    if vs["pool"] == pool:
                        self.logger.debug("Putting VS: {} into maintenance.".format(vs["name"]))
                        vtm.enable_maintenance(vs["name"], "maintenance")
            else:
                self.logger.debug("Pool not dead")
