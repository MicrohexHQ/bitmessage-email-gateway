#!/usr/bin/python2.7

import urlparse
import os
import base64
import email
import logging
import lib.payment
from lib.config import BMConfig
from lib.bmapi import BMAPI
from lib.msgtemplate import MsgTemplate

class SendBM(object):
	def __init__ (self, sender, recipient, subject, body):
		self.subject = base64.b64encode(subject)
		self.body = base64.b64encode(body)
		self.status = False
		self.ackdata = None
		if (sender[0:3] == "BM-"):
			senderbm = sender
		else:
			senderbm = BMAPI().get_address(sender)
		recipientbm = recipient
		userdata = lib.user.GWUser(bm = recipient)
		if userdata.check():
			recipient = userdata.email
		self.status = False
		try:
			ackData = BMAPI().conn().sendMessage(recipientbm, senderbm, self.subject, self.body, 2)
			logging.info("Sent BM from %s to %s: %s", sender, recipient, ackData)
			self.ackdata = ackData
			self.status = True
		except:
			logging.error("Failure sending BM from %s to %s", sender, recipient)

class SendBMTemplate(SendBM):
	def __init__ (self, sender, recipient, template, addmaps = None):
		maps = {'sender' : sender, 'recipient' : recipient }
		if isinstance(addmaps, dict):
			for key, value in addmaps.iteritems():
				maps[key] = value
			
		obj = MsgTemplate(maps = maps, base = template)
		#super(SendBMTemplate, self).__init__(self, sender = sender, recipient = recipient, subject = obj.subject(), body = obj.body())
		SendBM.__init__(self, sender = sender, recipient = recipient, subject = obj.getsubject(), body = obj.getbody())

#class RelayBM(SendBM):
	#def __init (self, sender, recipient):
		#maps
