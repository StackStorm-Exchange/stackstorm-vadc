#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Bsd


class BsdUnlicenseVtm(Action):

    def run(self, vtm):

        bsd = Bsd(self.config, self.logger)
        result = bsd.del_vtm(vtm)
        return (True, result)
