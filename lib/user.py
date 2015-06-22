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
		BMMySQL().db.ping(True)
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
				alias = GWAlias(email).target
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

	def check(self):
		return self.uid != None

	def add(self, bm, email, postmap = None):
		BMMySQL().db.ping(True)
		cur = BMMySQL().db.cursor()
		if postmap == None:
			postmap = pwd.getpwuid(os.getuid())[0]
		trash, domain = email.split("@")
		filterwarnings('ignore', category = MySQLdb.Warning)
		cur.execute ("""INSERT IGNORE INTO user (bm, email, postmap, domain, credits, exp, active, cansend, cancharge, caninvoice, attachments)
				VALUES (%s, %s, %s, %s, '0', '1971-01-01', 1, 1, 0, 0, 0)""", (bm, email, postmap, domain))
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
		BMMySQL().db.ping(True)
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

	def setlastrelay(self, lastrelay = None):
		BMMySQL().db.ping(True)
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

class GWAlias(object):
	def __init__(self, email):
		self.alias = None
		self.target = None
		BMMySQL().db.ping(True)
		cur = BMMySQL().db.cursor(MySQLdb.cursors.DictCursor)
		result = False
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

	def gettarget(self):
		return self.target

class GWDomain(object):
	def __init__(self, domain = None):
		self.name = None
		self.active = None
		BMMySQL().db.ping(True)
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

