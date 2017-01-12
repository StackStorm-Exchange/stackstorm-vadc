#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm


class VtmDisableSslOffload(Action):

    def run(self, vtm, name, xproto, headers):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.enable_ssl_offload(name, "", False, xproto, headers)
        return (True, None)
