#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm


class VtmRestoreBackup(Action):

    def run(self, vtm, name):

        vtm = Vtm(self.config, self.logger, vtm)
        output = vtm.restore_backup(name)
        return (True, output)
