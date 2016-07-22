#!/usr/bin/python2.7

from lib.config import BMConfig
from lib.mysql import BMMySQL
import MySQLdb
import lib.singleton
import os
import sys
import pwd
import datetime
import logging
from warnings import filterwarnings

class GWUser(object):
	def __init__(self, empty = False, bm = None, uid = None, email = None, unalias = False):
		if bm != None:
			self.load(bm = bm)
		elif uid != None:
			self.load(uid = uid)
		elif email != None:
			self.load(email = email, unalias = unalias)
		elif empty:
			self.uid = None
		else:
			# if no arguments, return all
			self.load()

	def load(self, bm = None, uid = None, email = None, unalias = False):
		BMMySQL().ping()
		cur = BMMySQL().db.cursor(MySQLdb.cursors.DictCursor)
		filterwarnings('ignore', category = MySQLdb.Warning)
		multirow = False
		self.uid = None
		if bm != None:
			cur.execute ("SELECT * FROM user WHERE bm = %s", (bm))
		elif uid != None:
			cur.execute ("SELECT * FROM user WHERE uid = %s", (uid))
		elif email != None:
			if unalias:
				alias = GWAlias(email = email).target
				if alias:
					email = alias
			cur.execute ("SELECT * FROM user WHERE email = %s", (email))
		else:
			# if no arguments, return all
			multirow = True
			cur.execute ("SELECT * FROM user ORDER BY email")

		for row in cur.fetchall():
			if multirow:
				print "%1s %-40s %-39s " % ("*" if row['active'] else " ", row['email'], row['bm'])
			else:
				for column in row:
					setattr(self, column, row[column])
		cur.close()
		if hasattr(self, 'email'):
			self.aliases = GWAlias(alias = self.email).aliases

	def check(self):
		return self.uid != None

	def expired(self):
		return self.exp < datetime.date.today()

	def add(self, bm, email, postmap = None):
		BMMySQL().ping()
		cur = BMMySQL().db.cursor()
		if postmap == None:
			postmap = pwd.getpwuid(os.getuid())[0]
		trash, domain = email.split("@")
		filterwarnings('ignore', category = MySQLdb.Warning)
		pgp = 1 if BMConfig().get("bmgateway", "default", "pgp") else 0
		attachments = 1 if BMConfig().get("bmgateway", "default", "attachments") else 0
		cur.execute ("""INSERT IGNORE INTO user (bm, email, postmap, domain, pgp, credits, exp, active, cansend, cancharge, caninvoice, attachments, html, lastackreceived)
				VALUES (%s, %s, %s, %s, %s, '0', '1971-01-01', 1, 1, 0, 0, %s, 0, UNIX_TIMESTAMP(NOW()))""", (bm, email, postmap, domain, pgp, attachments))
		uid = None
		if cur.rowcount == 1:
			uid = cur.lastrowid
			self.load(uid = uid)
			logging.info('Registered new user (%u) %s', uid, email)
		else:
			logging.error('Failed to add new user entry into the database for %s', email)
		cur.close()
		return uid

	def delete(self):
		BMMySQL().ping()
		cur = BMMySQL().db.cursor()
		filterwarnings('ignore', category = MySQLdb.Warning)
		if self.uid:
			cur.execute ("DELETE FROM user WHERE uid = %s", (self.uid))
			if (cur.rowcount == 1):
				logging.info('Deleted user (%u) %s / %s', self.uid, self.email, self.bm)
			elif (cur.rowcount > 1):
				logging.warning('Deleted user (%u) returned more than one row', self.uid)
		else:
			logging.info('Asked to delete nonexisting user')
		cur.close()

	def update(self, data):
		BMMySQL().ping()
		col_names = BMMySQL().filter_column_names("user", data)
		cur = BMMySQL().db.cursor()
		update_list = []
		for key in col_names:
			if data[key] is not None:
				update_list.append("`" + key + "`" + " = \"" + BMMySQL().db.escape_string(data[key]) + "\"")
		if len(update_list) == 0:
			return False
		cur.execute("UPDATE user SET " + ", ".join(update_list) + " WHERE bm = %s", (self.bm))
		#print ("UPDATE user SET " + ", ".join(update_list) + " WHERE bm = %s" % (self.bm))
		if cur.rowcount == 1:
			cur.close()
			return True
		else:
			cur.close()
			return False

	def setlastrelay(self, lastrelay = None):
		BMMySQL().ping()
		cur = BMMySQL().db.cursor()
		filterwarnings('ignore', category = MySQLdb.Warning)
		if lastrelay == None:
			cur.execute ("UPDATE user SET lastrelay = UNIX_TIMESTAMP() WHERE uid = %s", (self.uid))
		else:
			cur.execute ("UPDATE user SET lastrelay = %s WHERE uid = %s", (lastrelay, self.uid))
		if (cur.rowcount == 1):
			logging.debug('Set lastrelay for (%u)', self.uid)
		else:
			logging.warning('Failure setting lastrelay for (%u)', self.uid)
		cur.close()

	def setlastackreceived(self, lastackreceived = None):
		# for example user deleted
		if self.uid is None:
			return
		BMMySQL().ping()
		cur = BMMySQL().db.cursor()
		filterwarnings('ignore', category = MySQLdb.Warning)
		if lastackreceived == None:
			cur.execute ("UPDATE user SET lastackreceived = UNIX_TIMESTAMP() WHERE uid = %s", (self.uid))
		else:
			cur.execute ("UPDATE user SET lastackreceived = %s WHERE uid = %s", (lastackreceived, self.uid))
		if (cur.rowcount == 1):
			logging.debug('Set lastackreceived for (%u)', self.uid)
		else:
			logging.warning('Failure setting lastackreceived for (%u)', self.uid or -1)
		cur.close()

class GWUserData(object):

	@staticmethod
	def zero_one(text):
		text = text.lower()
		if text in ("1", "on", "true", "yes"):
			return "1"
		if text in ("0", "off", "false", "no"):
			return "0"
		else:
			return None
	@staticmethod
	def pgp(text):
		text = text.lower()
		if text in ("server"):
			return "1"
		if text in ("local"):
			return "0"
		else:
			return GWUserData.zero_one(text)

	@staticmethod
	def is_float(text):
		try:
			i = float(text)
			return True
		except (ValueError, TypeError):
			return False
		return False

	@staticmethod
	def numeric(text, decimals = 0):
		if decimals == 0:
			return text if text.isdigit else None
		elif isinstance(decimals, int) and decimals > 0 and decimals < 10:
			if GWUserData.is_float(text):
			 	return str(round(float(text),decimals))
			else:
				return None
		else:
			return None

	@staticmethod
	def public_seed(text):
		if not text.isalnum():
			return None
		# BIP32
		elif text[:4] == "xpub" and len(text) <= 112 and len(text) >= 100:
			return text
		# electrum
		elif len(text) == 32 or len(text) == 64:
			return text
		else:
			return None

	@staticmethod
	def currency(text):
		text = text.lower()
		if text in ("usd", "dollar"):
			return "USD"
		elif text in ("gbp", "pound", "sterling"):
			return "GBP"
		elif text in ("eur", "euro"):
			return "EUR"
		elif text in ("btc", "xbt", "bitcoin", "bitcoins"):
			return "BTC"
		else:
			return "BTC"

class GWAlias(object):
	def __init__(self, email = None, alias = None):
		self.aliases = []
		self.target = None
		BMMySQL().ping()
		cur = BMMySQL().db.cursor(MySQLdb.cursors.DictCursor)
		result = False
		if email:
			seen = {email: True}
			src = email
			while not result:
				cur.execute ("SELECT target FROM alias WHERE alias = %s", (src))
				result = True
				for row in cur.fetchall():
					result = False
					seen[row['target']] = True
					src = row['target']
					for column in row:
						setattr(self, column, row[column])
		elif alias:
			cur.execute ("SELECT alias FROM alias WHERE target = %s", (alias))
			for row in cur.fetchall():
				self.aliases.append(row['alias'])
		cur.close()

	def gettarget(self):
		return self.target

class GWDomain(object):
	def __init__(self, domain = None):
		self.name = None
		self.active = None
		BMMySQL().ping()
		cur = BMMySQL().db.cursor(MySQLdb.cursors.DictCursor)
		filterwarnings('ignore', category = MySQLdb.Warning)
		multirow = False
		if domain != None:
			cur.execute ("SELECT * FROM domain WHERE active = 1 AND name = %s", (domain))
		else:
			multirow = True
			cur.execute ("SELECT * FROM domain WHERE active = 1")
		for row in cur.fetchall():
			if multirow:
				print "%40s %1u" % (row['name'], row['active'])
			else:
				self.name = row['name']
				self.active = row['active']
		cur.close()

	def check(self):
		return self.name != None

