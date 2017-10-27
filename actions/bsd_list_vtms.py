#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Bsd


class BsdListVtms(Action):

    def run(self, full, deleted, stringify):

        bsd = Bsd(self.config, self.logger)
        result = bsd.list_vtms(full, deleted, stringify)
        return (True, result)
