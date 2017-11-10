#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Bsd


class BsdGetErrors(Action):

    def run(self, stringify):
        bsd = Bsd(self.config, self.logger)
        result = bsd.get_errors(stringify)
        return (True, result)
