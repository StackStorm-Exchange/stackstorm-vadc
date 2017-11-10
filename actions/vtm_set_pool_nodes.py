#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmSetPoolNodes(Action):

    def run(self, vtm, pool, active, draining, disabled):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.set_pool_nodes(pool, active, draining, disabled)
        return (True, None)
