#!/usr/bin/python2.7

import socket
import Milter
import Milter.utils
import hashlib
import MySQLdb
from lib.mysql import BMMySQL
from lib.config import BMConfig
import lib.user

class BMMilter(Milter.Base):
	def __init__ (self):
		self.mailfrom = None        # sender in SMTP form
		self.id = Milter.uniqueID()

	def envfrom (self, f, *str):
        	addr = Milter.utils.parse_addr(f.lower())
		if len(addr) == 2:
			self.mailfrom = addr[0] + "@" + addr[1]
		else:
			self.mailfrom = f.lower()
		return Milter.CONTINUE

	def envrcpt (self, to, *str):
		# <>
		if self.mailfrom == "":
			return Milter.CONTINUE
	
		# de +ify
        	addr = Milter.utils.parse_addr(to.lower())
		rcpt = addr[0] + "@" + addr[1]

		BMMySQL().db.ping(True)
		userdata = lib.user.GWUser(email = rcpt)

		# non exising user
		if not userdata.check():
			return Milter.CONTINUE

		if userdata.cancharge == 0 or userdata.masterpubkey_btc == None or userdata.feeamount == 0:
			return Milter.CONTINUE
		
		h = hashlib.new('sha256')
		h.update (self.mailfrom + "!" + rcpt);
		digest = h.digest()

		cur = BMMySQL().db.cursor(MySQLdb.cursors.DictCursor)

		cur.execute("SELECT id, status FROM sendercharge WHERE hash = %s", (digest))
		
		result = False
		for row in cur.fetchall():
			result = row

		if result and result['status'] == 1:
			cur.close()
			return Milter.CONTINUE

		if result: # result['status'] == 0
			cur.execute("SELECT address, amount FROM invoice WHERE sendercharge_id = %s", (row['id']))
			for row in cur.fetchall():
				result = row
			url = lib.payment.create_payment_url(result['address'], 'BTC', result['amount'], rcpt, 'Sending emails')
		else: # no record
			btcaddress, amount = lib.payment.create_invoice_user(rcpt)
			url = lib.payment.create_payment_url(btcaddress, 'BTC', amount, rcpt, 'Sending emails')
			cur.execute("INSERT INTO sendercharge (hash, status) values (%s, %s)", (digest, 0))
			sendercharge_id = cur.lastrowid
			cur.execute("UPDATE invoice SET sendercharge_id = %s WHERE address = %s and coin = 'BTC'", (sendercharge_id, btcaddress))
		cur.close()

		url = url.replace("%", "%%")
		self.setreply("550", "5.7.0", "PAYMENT REQUIRED: %s" % url)
		return Milter.REJECT

	# signal handlers
	def stop(self):
		return Milter.TEMPFAIL

	def abort(self):
		return Milter.TEMPFAIL

def run():
	Milter.factory = BMMilter
	socket.setdefaulttimeout(60)
	Milter.runmilter("bmmilter", BMConfig().get("bmgateway", "bmgateway", "miltersocket") ,600)
