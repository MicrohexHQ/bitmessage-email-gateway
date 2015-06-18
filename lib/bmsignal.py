#!/usr/bin/python

import signal, os
import lib.bmlogging

def huphandler(signum, frame):
	lib.bmlogging.init_logging()

#signal.signal(signal.SIGHUP, huphandler)
