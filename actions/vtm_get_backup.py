#! /usr/bin/python

from st2common.runners.base_action import Action
from lib.vadc import Vtm
from os import path
import sys


class VtmGetBackup(Action):

    def run(self, vtm, name, outdir):

        vtm = Vtm(self.config, self.logger, vtm)

        if path.isdir(outdir) is True:
            outfile = "{}/backup_{}_{}.tar".format(outdir, vtm.vtm, name)
            if path.exists(outfile) is False:
                fh = open(outfile, "wb")
                backup = vtm.get_backup(name)
                fh.write(backup)
                fh.close()
                return (True, outfile)
            else:
                sys.stderr.write("File exists: {}\n".format(outfile))
                return (False, None)
        else:
            sys.stderr.write("Outdir is not a directory!\n")
            return (False, None)
