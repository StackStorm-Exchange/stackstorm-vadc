#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm


class VtmAddPersistence(Action):

    def run(self, vtm, name, method, cookie):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.add_session_persistence(name, method, cookie)
