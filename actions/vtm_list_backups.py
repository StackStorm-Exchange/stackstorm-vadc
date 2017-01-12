#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm


class VtmListBackups(Action):

    def run(self, vtm):

        vtm = Vtm(self.config, self.logger, vtm)
        backups = vtm.list_backups()
        return (True, backups)
