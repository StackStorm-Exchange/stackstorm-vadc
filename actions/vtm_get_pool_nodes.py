#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmGetPoolNodes(Action):

    def run(self, vtm, pool):

        vtm = Vtm(self.config, self.logger, vtm)
        result = vtm.get_pool_nodes(pool)
        return (True, result)
