#!/usr/bin/python2.7

import xmlrpclib
import json
import lib.singleton
import logging
import threading # xmlrpc ServerProxy is not thread save, so we need a separate object for each thread
from lib.config import BMConfig

class BaseBMAPI(object):
	thrdata = None
	address_list = {}

	def __init__(self):
		self.thrdata = threading.local()
		self.connect()
		self._load_address_list()

	def check_connection(self):
		if not (hasattr(self.thrdata, 'bm') and self.thrdata.bm is not None):
			self.connect()
		if not bool(self.address_list):
			self._load_address_list()
		return self.thrdata.bm

	def connect(self):
		for bm in BMConfig().get("bmapi"):
			self.thrdata.bm = xmlrpclib.ServerProxy('http://' +
				BMConfig().get("bmapi", bm, "username") + ':' +
				BMConfig().get("bmapi", bm, "password") + '@' +
				BMConfig().get("bmapi", bm, "host") + ':' +
				str(BMConfig().get("bmapi", bm, "port")) + '/')

			## check if API is responding
			try:
				response = self.thrdata.bm.add(2,2)
				logging.info("Connected to Bitmessage API on %s:%i", BMConfig().get("bmapi", bm, "host"), BMConfig().get("bmapi", bm, "port"))
				break
			except:
				self.thrdata.bm = None
		if self.thrdata.bm is not None:
			return self.thrdata.bm
		else:
			logging.error('Could not connect to Bitmessage API ')
		return False

	def _load_address_list(self):
		# does not check for connection, only use internally
		self.address_list = {}
		bm_addresses = json.loads(self.thrdata.bm.listAddresses())['addresses']
		for address in bm_addresses:
			self.address_list[address['label']] = address['address']

	def get_address(self, label):
		if not bool(self.address_list):
			self.check_connection()
		if label in self.address_list:
			return self.address_list[label]
		else:
			return None

	def conn(self):
		return self.check_connection()

	def disconnect(self):
		self.thrdata.bm = None

class BMAPI(BaseBMAPI):
	__metaclass__ = lib.singleton.Singleton
