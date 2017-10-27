#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Bsd


class BsdGetActiveVtm(Action):

    def run(self, vtms, cluster):
        bsd = Bsd(self.config, self.logger)
        result = bsd.get_active_vtm(vtms, cluster)
        if result is None:
            return (False, result)
        return (True, result)
