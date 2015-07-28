#!/usr/bin/python

import lib.singleton
import ConfigParser, os

class BaseBMConfig(object):
	files = {
		"bmgateway": 0,
		"pgpkeyservers": 0,
		"bmapi": 0,
		"smtp": 0,
		"mysql": 0
	}
	valuetypes = {
		"bmgateway": {
			"banned_usernames": "boolean",
			"bmgateway": {
				"debug": "boolean",
				"respond_to_invalid": "boolean",
				"respond_to_missing": "boolean",
				"allow_unregistered_senders": "boolean",
				"throttle": "float",
				"incoming_thread": "int",
				"outgoing_thread": "int",
				"pgp_thread": "boolean",
				"milter_thread": "boolean",
				"process_interval": "float",
				"outbox_process_interval": "float"
			},
			"pgp": {
				"sign": "boolean",
				"encrypt": "boolean",
				"delete_expired_delay": "int"
			},
			"bitcoind": {
				"port": "int"
			}
		},
		"bmapi": {
			"*": {
				"port": "int"
			}
		},
		"smtp": {
			"*": {
				"port": "int"
			}
		}
	}
	cfg = {}

	@staticmethod
	def getvaluetype (fname, section, option):
		try:
			return BaseBMConfig.valuetypes[fname][section][option]
		except:
			pass
		try:
			return BaseBMConfig.valuetypes[fname]["*"][option]
		except:
			pass
		try:
			return BaseBMConfig.valuetype[fname][section]
		except:
			pass
		try:
			return BaseBMConfig.valuetype[fname]
		except:
			pass
	
		#default
		return "text"

	def __init__(self):
		self.loadconf()

	def loadconf(self):
		tmp = {}
		dataFolder = os.path.join (os.environ["HOME"], ".config", "bmgateway")
		for fname in BaseBMConfig.files:
			config = ConfigParser.SafeConfigParser(allow_no_value=True)
			config.readfp(open(os.path.join(dataFolder, fname + ".conf")))
			tmp[fname] = {}
			for section in config.sections():
				tmp[fname][section] = {}
				for option in config.options(section):
					vtype = BaseBMConfig.getvaluetype(fname, section, option)
					if vtype == "boolean":
						tmp[fname][section][option] = config.getboolean(section, option)
					elif vtype == "int":
						tmp[fname][section][option] = config.getint(section, option)
					elif vtype == "float":
						tmp[fname][section][option] = config.getfloat(section, option)
					else:
						tmp[fname][section][option] = config.get(section, option)
		self.cfg = tmp

	def get(self, fname, section = None, option = None):
		if (section == None):
			try:
				return self.cfg[fname]
			except KeyError:
				return None
		elif (option == None):
			try:
				return self.cfg[fname][section]
			except KeyError:
				return None
		else:
			try:
				return self.cfg[fname][section][option]
			except KeyError:
				return None
		return None

class BMConfig(BaseBMConfig):
	__metaclass__ = lib.singleton.Singleton
