#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm


class VtmAddPool(Action):

    def run(self, vtm, name, nodes, algorithm, persistence, monitors, extra):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.add_pool(name, nodes, algorithm, persistence, monitors, extra)
