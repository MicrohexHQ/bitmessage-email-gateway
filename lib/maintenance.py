#!/usr/bin/python2.7

from lib.mysql import BMMySQL

class MaintenanceThread (object):
	def getSchedule(key):
		cur = BMMySQL().conn().cursor(MySQLdb.cursors.DictCursor)
		cur.execute ("SELECT ts FROM schedules WHERE id = %s", (key))
		ret = None
		for row in cur.fetchall():
			ret = row['ts']
		cur.close()
		return ret

	def sanitisePayments():
		return None
	
	def revokeOldPGP():
		return None

	def deleteOldPGP():
		return None

	def generateNewPGP():
		return None

	def deleteOldMEGA():
		return None

	def notifyExpiration():
		for days in (1, 3, 7):
			pass
		return None

def maintenance_thread():
	pass
