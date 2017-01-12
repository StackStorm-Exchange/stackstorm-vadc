#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Bsd


class BsdListVtms(Action):

    def run(self, full, deleted, stringify):

        bsd = Bsd(self.config, self.logger)
        result = bsd.list_vtms(full, deleted, stringify)
        return (True, result)
