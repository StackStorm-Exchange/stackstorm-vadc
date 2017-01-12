#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm
from os import path
import sys


class VtmAddBackup(Action):

    def run(self, vtm, tarball):

        vtm = Vtm(self.config, self.logger, vtm)

        if path.exists(tarball) is True:
            fh = open(tarball, "rb")
            backup = fh.read()
            fh.close()
        else:
            sys.stderr.write("File does not exist: {}\n".format(tarball))
            return (False, None)

        result = vtm.upload_backup(backup)
        return (True, result)
