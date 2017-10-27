#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmMaintenanceMode(Action):

    def run(self, vtm, vserver, rule, enable):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.enable_maintenance(vserver, rule, enable)
        return (True, None)
