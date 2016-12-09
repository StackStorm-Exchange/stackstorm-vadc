#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm


class VtmSetPoolNodes(Action):

    def run(self, vtm, pool, active, draining, disabled):

        vtm = Vtm(self.config, self.logger, vtm)
        result = vtm.set_pool_nodes(pool, active, draining, disabled)
        return (True, None)
