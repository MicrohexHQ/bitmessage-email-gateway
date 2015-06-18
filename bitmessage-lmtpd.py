#!/bin/env python

import asyncore
import lib.lmtpd

server = lib.lmtpd.LMTPServer(('localhost', 10025), None)
 
asyncore.loop()
