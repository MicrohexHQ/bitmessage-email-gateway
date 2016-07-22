#!/usr/bin/python2.7

import jsonrpclib
import MySQLdb
import sys
import hashlib
import datetime
import decimal

from lib.config import BMConfig
from lib.mysql import BMMySQL
from lib.bmlogging import BMLogging
from lib.user import GWUser
from lib.bmapi import BMAPI
from lib.sendbm import SendBMTemplate

from warnings import filterwarnings

def parse_configfile(fname):
	ret = {
		'rpcport': 8332,
		'rpcuser': '',
		'rpcpassword': '',
		'rpcconnect': '127.0.0.1'
	}
	from os.path import expanduser

	fname = expanduser(fname)
	with open(fname) as f:
		for line in f.read().splitlines():
			try:
				key, val = line.split("=")
			except:
				continue
			if not key:
				continue
			if key in ret:
				ret[key] = val
	return ret

if len(sys.argv) < 3:
	print "Must specify coin (BTC or DRK) and txid"
	sys.exit()

coin = sys.argv[1]
txid = sys.argv[2]

if coin == 'BTC':
	cfg = parse_configfile('~/.bitcoin/bitcoin.conf')
elif coin == 'DRK':
	cfg = parse_configfile('~/.dash/dash.conf')
else:
	print "Unknown coin " + coin
	sys.exit()

client = jsonrpclib.Server('http://' + cfg['rpcuser'] + ":" + cfg['rpcpassword'] + "@" + cfg['rpcconnect'] + ":" + str(cfg['rpcport']) + "/")

txinfo = client.gettransaction(txid, True)

BMLogging()
BMMySQL().connect()
cur = BMMySQL().db.cursor(MySQLdb.cursors.DictCursor)
while BMAPI().conn() is False:
	print "Failure connecting to API, sleeping..."
	time.sleep(random.random()+0.5)

filterwarnings('ignore', category = MySQLdb.Warning)

#amount = txinfo['amount']
for detail in txinfo['details']:
	if detail['category'] == "receive":
		print detail['address'] + " -> " + str(detail['amount'])
		cur.execute ( """INSERT IGNORE INTO payment (address, coin, txid, amount, confirmations) VALUES (%s, %s, %s, %s, %s)""",
			(detail['address'], coin, txid, detail['amount'], txinfo['confirmations']))
		if txinfo['confirmations'] == 0:
			# select from invoice
			cur.execute ("SELECT amount, paid, type, payer, sendercharge_id FROM invoice WHERE address = %s AND coin = %s", (detail['address'], coin))
			for row in cur.fetchall():
				invoice = row
			# fetch
			totalpaid = 0
			cur.execute ("SELECT amount FROM payment WHERE address = %s AND coin = %s AND confirmations = 0", (detail['address'], coin))
			for row in cur.fetchall():
				payment = row
				totalpaid += payment['amount'] # fixme floating rounding problems?
			# fetch
			if invoice['paid'] == None or invoice['paid'] <= datetime.datetime(1971, 1, 1) and totalpaid >= invoice['amount']:
				cur.execute ("UPDATE invoice SET paid = NOW() WHERE address = %s AND coin = %s ", (detail['address'], coin))
				if invoice['type'] == 0:
					incomingamount = decimal.Decimal(str(detail['amount']))
					if incomingamount < invoice['amount']:
						months = 0
					else:
						months = incomingamount / invoice['amount']
					print "Extending for " + str(months) + " months"
					userdata = GWUser(bm = invoice['payer'])
					if not hasattr(userdata, "exp"):
						# user was deleted
						continue
					datefrom = userdata.exp if userdata.exp > datetime.date.today() else datetime.date.today()
					cur.execute ("UPDATE user SET cansend = 1, exp = IF(exp < CURDATE(),DATE_ADD(CURDATE(), INTERVAL " +
						str(months) + " MONTH),DATE_ADD(exp, INTERVAL " + str(months) +
						" MONTH)) WHERE bm = %s", invoice['payer']);
					userdata = GWUser(bm = invoice['payer'])
					dateuntil = userdata.exp
					SendBMTemplate(
						sender = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "registration_address_label")),
						recipient = invoice['payer'],
						template = "invoice",
                                                addmaps = {
							'btcamount': str(incomingamount),
                                                        'service': 'Subscription for ' + userdata.email + ' from ' + datefrom.strftime("%B %-d %Y") +
                                                                ' until ' + dateuntil.strftime("%B %-d %Y"),
                                                        'email': userdata.email
                                                })

				elif invoice['type'] == 1:
					# find in combo table and allow
					cur.execute ("UPDATE sendercharge SET status = 1 WHERE id = %s", (invoice['sendercharge_id']))
				elif invoice['type'] == 2:
					# notify user that payment is incoming
					pass
			pass
cur.close()
