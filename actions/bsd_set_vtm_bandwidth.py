#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Bsd


class BsdSetVtmBandwidth(Action):

    def run(self, vtm, bw):

        bsd = Bsd(self.config, self.logger)
        bsd.set_bandwidth(vtm, bw)
