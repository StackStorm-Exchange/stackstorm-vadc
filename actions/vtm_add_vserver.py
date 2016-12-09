#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm


class VtmAddVserver(Action):

    def run(self, vtm, name, pool, tip, port, protocol, extra):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.add_vserver(name, pool, tip, port, protocol, extra)
