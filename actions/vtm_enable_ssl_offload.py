#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmEnableSslOffload(Action):

    def run(self, vtm, name, cert, xproto, headers):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.enable_ssl_offload(name, cert, True, xproto, headers)
        return (True, None)
