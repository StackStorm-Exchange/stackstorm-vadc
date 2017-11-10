#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Bsd


class BsdLicenseVtm(Action):

    def run(self, vtm, password, address, bw, fp):

        bsd = Bsd(self.config, self.logger)
        result = bsd.add_vtm(vtm, password, address, bw, fp)
        return (True, result)
