#!/usr/bin/python2.7

import logging
import json
from lib.config import BMConfig
from lib.bmapi import BMAPI

class BMMessage(object):
	def __init__ (self, msgid, folder = "inbox"):
		if folder == "inbox":
			try:
				self.msg = json.loads(BMAPI().conn().getInboxMessageByID(msgid, False))['inboxMessage'][0]
			except:
				logging.error('API error when retrieving inbox message %s', msgid)
				pass
		if not self.msg:
			logging.error('API returned blank message when retrieving inbox message %s', msgid)
#			deleteStatic(msgid)
		self.folder = folder
		self.msgid = self.msg['msgid']

	def delete (self):
		return deleteStatic(self.msgid, folder = self.folder)

	@staticmethod
	def deleteStatic (msgid, folder = "inbox"):
		if folder == "inbox":
			result = BMAPI().conn().trashMessage(msgid)
		elif folder == "outbox":
			result = BMAPI().conn().trashSentMessage(msgid)
		if BMConfig().get("bmgateway", "bmgateway", "debug"):
			logging.debug('Deleted bitmessage %s from %s, API response: %s', msgid, folder, result)
		else:
			logging.info('Deleted bitmessage %s from %s', msgid, folder)

