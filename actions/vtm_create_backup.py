#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm


class VtmCreateBackup(Action):

    def run(self, vtm, name, description):

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.create_backup(name, description)
        return (True, None)
