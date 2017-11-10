#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmDeleteBackup(Action):

    def run(self, vtm, name):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.delete_backup(name)
        return (True, None)
