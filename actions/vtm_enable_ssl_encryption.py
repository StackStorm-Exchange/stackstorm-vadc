#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmEnableSslEncryption(Action):

    def run(self, vtm, name, verify):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.enable_ssl_encryption(name, True, verify)
        return (True, None)
