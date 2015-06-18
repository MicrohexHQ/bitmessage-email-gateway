#!/usr/bin/python

import logging
import logging.handlers
import lib.singleton
from lib.config import BMConfig

class BaseBMLogging(object):
	logger = None
	handler = None
	formatter = None

	def __init__(self):
		self.logger = logging.getLogger()
		if BMConfig().get("bmgateway", "bmgateway", "debug"):
			self.logger.setLevel(logging.DEBUG)
		else:
			self.logger.setLevel(logging.INFO)
		self.handler = logging.handlers.WatchedFileHandler(BMConfig().get("bmgateway", "bmgateway", "log_filename"))
		self.formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
		self.handler.setFormatter(self.formatter)
		self.logger.addHandler(self.handler)

class BMLogging(BaseBMLogging):
	__metaclass__ = lib.singleton.Singleton
