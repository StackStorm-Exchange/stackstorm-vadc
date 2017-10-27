#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmAddServerCert(Action):

    def run(self, vtm, name, public, private):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.add_server_cert(name, public, private)
