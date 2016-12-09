#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm


class VtmAddTip(Action):

    def run(self, vtm, name, vtms, addresses, extra):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.add_tip(name, vtms, addresses, extra)
