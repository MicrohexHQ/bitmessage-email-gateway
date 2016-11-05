#!/usr/bin/python2.7

import urllib, json
import qrcode
import base64
import bitcoin
import MySQLdb
import StringIO
import jsonrpclib
import decimal
from warnings import filterwarnings
from lib.config import BMConfig
from lib.mysql import BMMySQL

def create_payment_url(address, currency, amount, label, message):
	base = "https://mailchuck.com/payment/#"
	base += create_payment_uri(address, currency, amount, label, message)
	return base

def create_payment_uri(address, currency, amount, label, message):
	base = "bitcoin:" + address
	if currency in ("USD", "GBP", "EUR"):
		amount /= get_bitcoin_price(currency)
	amount = "%.8f" % amount
	base += "?amount=" + amount
	base += "&label=" + urllib.quote(label, safe='~()*!.\'')
	base += "&message=" + urllib.quote(message, safe='~()*!.\'')
	return base

def payment_exists_domain (domain, payer):
	cur = BMMySQL().conn().cursor(MySQLdb.cursors.DictCursor)
	cur.execute ("SELECT address, amount FROM invoice WHERE type = 0 AND payer = %s AND paid = '0000-00-00 00:00:00'", (payer))
	result = False
	for row in cur.fetchall():
		result = row
	if result:
		return result['address'], result['amount']
	cur.close()
	return False, False
		

def create_invoice_domain (domain, payer):
	cur = BMMySQL().conn().cursor(MySQLdb.cursors.DictCursor)
	filterwarnings('ignore', category = MySQLdb.Warning)
	cur.execute ("SELECT bm, masterpubkey_btc, offset_btc, feeamount, feecurrency FROM domain WHERE name = %s AND active = 1", (domain))
	result = False
	for row in cur.fetchall():
		result = row
	while result:
		if result['masterpubkey_btc'][0:4] == "xpub":
			# BIP44
			dpk1 = bitcoin.bip32_ckd(result['masterpubkey_btc'], 0)
			dpk2 = bitcoin.bip32_ckd(dpk1, result['offset_btc'])
			pubkey = bitcoin.bip32_extract_key(dpk2)
		else:
			# Electrum 1.x
			pubkey = bitcoin.electrum_pubkey(result['masterpubkey_btc'], result['offset_btc'])
		address = bitcoin.pubkey_to_address(pubkey)
		bitcoind_importaddress(address)
		cur.execute ("UPDATE domain SET offset_btc = offset_btc + 1 WHERE name = %s AND active = 1 AND masterpubkey_btc = %s", (domain, result['masterpubkey_btc']))
		if result['feecurrency'] in ("USD", "GBP", "EUR"):
			result['feeamount'] /= decimal.Decimal(get_bitcoin_price(result['feecurrency']))
		cur.execute ("INSERT IGNORE INTO invoice (issuer, payer, address, coin, amount, type, paid) VALUES (%s, %s, %s, 'BTC', %s, 0, 0)", (result['bm'], payer, address, result['feeamount']))

		# invoice already exists for that address, increment
		if cur.rowcount == 0:
			cur.execute ("SELECT bm, masterpubkey_btc, offset_btc, feeamount, feecurrency FROM domain WHERE name = %s AND active = 1", (domain))
			result = False
			for row in cur.fetchall():
				result = row
			continue
		
		cur.close()
		return address, result['feeamount'];
	cur.close()
	return False


def create_invoice_user (email):
	cur = BMMySQL().conn().cursor(MySQLdb.cursors.DictCursor)
	cur.execute ("SELECT bm, masterpubkey_btc, offset_btc, feeamount, feecurrency FROM user WHERE email = %s AND active = 1", (email))
	result = False
	for row in cur.fetchall():
		result = row
	if result:
		if result['masterpubkey_btc'][0:4] == "xpub":
			# BIP44
			dpk1 = bitcoin.bip32_ckd(result['masterpubkey_btc'], 0)
			dpk2 = bitcoin.bip32_ckd(dpk1, result['offset_btc'])
			pubkey = bitcoin.bip32_extract_key(dpk2)
		else:
			# Electrum 1.x
			pubkey = bitcoin.electrum_pubkey(result['masterpubkey_btc'], result['offset_btc'])
		address = bitcoin.pubkey_to_address(pubkey)
		bitcoind_importaddress(address)
		cur.execute ("UPDATE user SET offset_btc = offset_btc + 1 WHERE email = %s AND active = 1 AND masterpubkey_btc = %s", (email, result['masterpubkey_btc']))
		if result['feecurrency'] in ("USD", "GBP", "EUR"):
			result['feeamount'] /= decimal.Decimal(get_bitcoin_price(result['feecurrency']))
		cur.execute ("INSERT INTO invoice (issuer, address, coin, amount, type, paid) VALUES (%s, %s, 'BTC', %s, 1, 0)", (result['bm'], address, result['feeamount']))
		cur.close()
		return address, result['feeamount'];
	cur.close()
	return False

def get_bitcoin_price (currency):
	if currency in ("USD", "GBP", "EUR"):
		url = 'https://api.coindesk.com/v1/bpi/currentprice.json'
		response = urllib.urlopen(url)
		data = json.loads(response.read())
		return data['bpi'][currency]['rate_float']
	else:
		return False

def bitcoind_importaddress (address):
	bitcoinrpc = jsonrpclib.Server('http://' + 
		BMConfig().get("bmgateway", "bitcoind", "username") + ":" +
		BMConfig().get("bmgateway", "bitcoind", "password") + "@" +
		BMConfig().get("bmgateway", "bitcoind", "host") + ":" +
		str(BMConfig().get("bmgateway", "bitcoind", "port")) + "/")
	# returns null on success
	rpcreply = bitcoinrpc.importaddress(address, "", False)

def qrcode_encoded(data):
	qr = qrcode.QRCode(version = None, error_correction = qrcode.constants.ERROR_CORRECT_L, box_size = 5, border = 4)
	qr.add_data(data)
	qr.make(fit=True)
	img = qr.make_image()
	tmp = StringIO.StringIO()
	img.save(tmp)
	out = "data:image/png;base64," + base64.b64encode(tmp.getvalue())
	tmp.close()
	return out
