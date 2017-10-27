#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmDelPool(Action):

    def run(self, vtm, name):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.del_tip(name)
        return (True, None)
