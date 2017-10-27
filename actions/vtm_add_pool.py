#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmAddPool(Action):

    def run(self, vtm, name, nodes, algorithm, persistence, monitors, extra):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.add_pool(name, nodes, algorithm, persistence, monitors, extra)
