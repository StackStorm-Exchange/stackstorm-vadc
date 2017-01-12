#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm


class VtmEnableSslEncryption(Action):

    def run(self, vtm, name, verify):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.enable_ssl_encryption(name, True, verify)
        return (True, None)
