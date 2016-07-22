#!/usr/bin/python2.7

from lib.config import BMConfig
import lib.singleton
import os
import sys
import time
import MySQLdb
import MySQLdb.converters
from MySQLdb.constants import FIELD_TYPE
from warnings import filterwarnings

class BaseBMMySQL(object):
	db = None

	def __init__(self):
		self.db = self.connect()

	def connect(self):
		orig_conv = MySQLdb.converters.conversions
		#Adding support for bit data type
		orig_conv[FIELD_TYPE.BIT] = bool

		for mysql in BMConfig().get("mysql"):
			if BMConfig().get("mysql", mysql, "unix_socket"):
				try:
					self.db =  MySQLdb.connect(unix_socket = BMConfig().get("mysql", mysql, "unix_socket"),
						user = BMConfig().get("mysql", mysql, "user"),
						passwd = BMConfig().get("mysql", mysql, "passwd"),
						db = BMConfig().get("mysql", mysql, "db"), conv = orig_conv)
					return self.db
				except MySQLdb.Error, e:
					print "MySQLdb.Error is %d: %s" % (e.args[0], e.args[1])
					continue
				except:
					print "Error connecting to " + mysql
					continue
			elif BMConfig().get("mysql", mysql, "host"):
				try:
					self.db =  MySQLdb.connect(host = BMConfig().get("mysql", mysql, "host"),
						user = BMConfig().get("mysql", mysql, "user"),
						passwd = BMConfig().get("mysql", mysql, "passwd"),
						db = BMConfig().get("mysql", mysql, "db"))
					return self.db
				except MySQLdb.Error, e:
					print "MySQLdb.Error is %d: %s" % (e.args[0], e.args[1])
					continue
				except:
					print "Error connecting to " + mysql
					continue
			else:
				self.db = None
				print "No host or unix socket in mysql definition for " + mysql
		return False

	def ping(self):
		ok = False
		while not ok:
			try:
				self.db.ping(True)
				ok = True
			except:
				if not self.connect():
					time.sleep(5)

	def filter_column_names (self, table, data):
		self.ping()
		cur = self.db.cursor()
		cur.execute("SHOW COLUMNS FROM user")
		all_column_names = {}
		for row in cur.fetchall():
			all_column_names[row[0]] = True
		cur.close()
		column_names = {}
		for key in data:
			if key in all_column_names:
				column_names[key] = data[key]
		return column_names


class BMMySQL(BaseBMMySQL):
	__metaclass__ = lib.singleton.Singleton
