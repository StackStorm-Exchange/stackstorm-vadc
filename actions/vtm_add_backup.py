#! /usr/bin/python

import sys
from os import path
from st2common.runners.base_action import Action
from lib.vadc import Vtm


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
