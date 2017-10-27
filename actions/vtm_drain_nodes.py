#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmDrainNodes(Action):

    def run(self, vtm, pool, nodes, drain):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.drain_nodes(pool, nodes, drain)
        return (True, None)
