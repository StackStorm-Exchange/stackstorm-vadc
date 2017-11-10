#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmRestoreBackup(Action):

    def run(self, vtm, name):

        vtm = Vtm(self.config, self.logger, vtm)
        output = vtm.restore_backup(name)
        return (True, output)
