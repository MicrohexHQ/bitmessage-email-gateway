#!/usr/bin/python

import gnupg
import email
import urllib
import urllib2
import re
import logging
import time
from lib.config import BMConfig
from lib.mysql import BMMySQL
import lib.unicode
import MySQLdb
from BeautifulSoup import BeautifulSoup
import datetime
import time
import traceback
import os
import pyme.core
import pyme.errors
import pyme.constants
#import hkp

#init
## GPG key cache
#gpgme.set_protocol(OpenPGP)
gpg = None
gpgme = None

class KeyEditor:
	def __init__(self, mode):
		if mode == "addkey":
			self.steps = ["addkey", "quit"]
		elif mode == "delkey":
			self.steps = ["expired_keynum", "delkey", "quit"]
		elif mode == "revkey":
			self.steps = ["revkey", "quit"]
		self.step = 0

	def edit_fnc(self, status, args, out):
#		print "[-- Response --]"
#		out.seek(0,0)
#		print out.read(),
#		print "[-- Code: %d, %s --]" % (status, args)
		out.seek(0,0)

		if args == "keyedit.prompt":
			if self.steps[self.step] == "expired_keynum":
				#sub:u:4096:1:39044548FE31C29F:1428010312:1428615112:::

				keynum = 0
				result = "help"

				for line in out.read().splitlines():
					items = line.split(":")
					if items[0] == "sub":
						keynum += 1
						if int(items[6]) + BMConfig().get("bmgateway", "pgp", "delete_expired_delay") < time.time():
							print "Key " + str(keynum) + " is expired"
							result = "key " + str(keynum)
							break
			else:
				result = self.steps[self.step]
			self.step += 1
		elif args == "keyedit.save.okay":
			result = "Y"
		elif args == "keyedit.remove.subkey.okay":
			result = "Y"
		elif args == "keyedit.revoke.subkey.okay":
			result = "Y"
		elif args == "ask_revocation_reason.code":
			result = "3"
		elif args == "ask_revocation_reason.text":
			result = ""
		elif args == "ask_revocation_reason.okay":
			result = "Y"
		elif args == "keygen.algo":
			result = "6"
		elif args == "keygen.size":
			result = "4096"
		elif args == "keygen.valid":
			result = BMConfig().get("bmgateway", "pgp", "expire_subkey")
		else:
			result = None

		return result

def gpg_init():
	global gpg
	global gpgme
	os.environ["GNUPGHOME"] = BMConfig().get("bmgateway", "pgp", "home")
	gpg = gnupg.GPG(gnupghome=BMConfig().get("bmgateway", "pgp", "home"), verbose=False)
	gpgme = pyme.core.Context()
#	gpgme.set_keylist_mode(pyme.constants.KEYLIST_MODE_LOCAL | pyme.constants.KEYLIST_MODE_EXTERN)

## encrypt text
def encrypt_text(text, recipient_key, sender_key = None):
	global gpgme
	plain = pyme.core.Data(lib.unicode.to_string(text))
	encrypted = pyme.core.Data()
	if sender_key:
		gpgme.signers_clear()
		if sender_key.can_sign:
			gpgme.signers_add(sender_key)
		if not gpgme.signers_enum(0):
			# can't sign
			return False
	gpgme.set_armor(1)
#	if not recipient_key.can_encrypt:
#		return False
	if sender_key:
		gpgme.op_encrypt_sign ([recipient_key], 1, plain, encrypted)
		logging.info('GPG encrypted to %s, signed by %s' % (recipient_key.subkeys[0].fpr[-8:], sender_key.subkeys[0].fpr[-8:]))
	else:
		logging.info('GPG encrypted to %s, no signature' % (recipient_key.subkeys[0].fpr[-8:]))
		gpgme.op_encrypt ([recipient_key], 1, plain, encrypted)
	encrypted.seek (0, 0)
	return encrypted.read()
	#return str(gpg.encrypt(text, fingerprint, always_trust = True, sign = sign))

def sign_text(text, key):
#	global gpg
	global gpgme
	plain = pyme.core.Data(lib.unicode.to_string(text))
	signed = pyme.core.Data()
	gpgme.signers_clear()
	if key.can_sign:
		gpgme.signers_add(key)
	if not gpgme.signers_enum(0):
		# can't sign
		return False
	gpgme.op_sign (plain, signed, pyme.pygpgme.GPGME_SIG_MODE_CLEAR)
	logging.info('GPG signed by %s, not encrypted' % (key.subkeys[0].fpr[-8:]))
	signed.seek (0, 0)

	return str(signed.read())

## add GPG locally
def import_key(data):
#	global gpg
#	import_result = gpg.import_keys(key)		
#	logging.info('Imported GPG key')
#	return import_result
	global gpgme
	if isinstance(data, unicode):
		newkey = pyme.core.Data(data.encode("utf-8"))
	else:
		newkey = pyme.core.Data(data)
	gpgme.op_import(newkey)
	logging.info('Imported GPG key')
	result = gpgme.op_import_result()
	if result:
		for k in dir(result):
			break
			if not k in result.__dict__ and not k.startswith("_"):
				if k == "imports":
					print k, ":",
					for impkey in result.__getattr__(k):
                    				print "    fpr=%s result=%d status=%x" % \
                          				(impkey.fpr, impkey.result, impkey.status)
				else:
					print k, ":", result.__getattr__(k)
		#FIXME this might not work always
		if result.imported > 0 or result.unchanged > 0:
			return True
	return False


def list_keys(searchtext = None):
	global gpgme
	gpgme.op_keylist_start(searchtext, 0)
	# FIXME this does not work
	entries = []
	while True:
		key = gpgme.op_keylist_next()
		if not key:
			break
		entry = {}
		entry['uids'] = []
		for uid in key.uids:
			entry['uids'].append(uid.email.lower())
		#print key.uids[0].email.lower() + otheruids + (", expired" if key.expired == 1 else "")
		entry['disabled'] = key.disabled
		entry['expired'] = key.expired
		entry['revoked'] = key.revoked
		entry['subkeys'] = []
		for subkey in key.subkeys:
			subentry = {}
			subentry['expires'] = subkey.expires
			subentry['expired'] = subkey.expired
			subentry['revoked'] = subkey.revoked
			subentry['disabled'] = subkey.disabled
			subentry['secret'] = subkey.secret
			subentry['invalid'] = subkey.invalid
			subentry['keyid'] = subkey.keyid
			subentry['fpr'] = subkey.fpr
			subentry['can_encrypt'] = subkey.can_encrypt
			subentry['can_sign'] = subkey.can_sign
			entry['subkeys'].append(subentry)
		entries.append(entry)
#		pprint.pprint (key.subkeys)
		#pprint.pprint (key)
	
#		print "signature", index, ":"

#		print "  summary:    ", sign.summary
#		print "  status:     ", sign.status
#		print "  timestamp:  ", sign.timestamp
#		print "  fingerprint:", sign.fpr
#		print "  email:      ", gpgme.get_key(sign.fpr, 0).uids[0].email.lower()
#		print "  uid:        ", gpgme.get_key(sign.fpr, 0).uids[0].uid
	return entries
	

def key_to_mysql(key):
	# stupid gpgme library has no support for exporting secret keys
	global gpg
	public = gpg.export_keys(key.subkeys[0].fpr) # Public
	secret = gpg.export_keys(key.subkeys[0].fpr, True) # Private

	rowcount = 0

	cur = BMMySQL().db.cursor()
	cur.execute ("INSERT INTO gpg (email, fingerprint, private, exp, data) VALUES (%s, %s, %s, FROM_UNIXTIME(%s), %s) ON DUPLICATE KEY UPDATE exp = VALUES(exp), data = VALUES(data)",
		(key.uids[0].email, key.subkeys[0].fpr, 0, key.subkeys[0].expires, public))
	rowcount += cur.rowcount
	cur.execute ("INSERT INTO gpg (email, fingerprint, private, exp, data) VALUES (%s, %s, %s, FROM_UNIXTIME(%s), %s) ON DUPLICATE KEY UPDATE exp = VALUES(exp), data = VALUES(data)",
		(key.uids[0].email, key.subkeys[0].fpr, 1, key.subkeys[0].expires, secret))
	rowcount += cur.rowcount
	return rowcount

def key_from_mysql(key):
	cur = BMMySQL().db.cursor(MySQLdb.cursors.DictCursor)
	logging.info("Importing GPG keys from SQL for %s", key)
	cur.execute ("SELECT data FROM gpg WHERE email = %s", (key))
	for row in cur.fetchall():
		import_key(row['data'])

def create_primary_key(address):
	global gpgme
	gpgme.set_armor(1)
	params = """<GnupgKeyParms format="internal">
	Key-Type: RSA
	Key-Length: 4096
	Key-Usage: sign,auth
	Name-Real: """ + address + """
	Name-Email: """ + address + """
	Name-Comment: Generated by mailchuck
	Expire-Date: """ + BMConfig().get("bmgateway", "pgp", "expire") + """
	</GnupgKeyParms>
	"""
	gpgme.op_genkey(params, None, None)
	key = check_key(address, whatreturn="key", operation="sign")
	key_to_mysql(key)
	return upload_key(key)

def create_subkey(address):
	global gpgme

	out = pyme.core.Data()
	key = check_key(address, whatreturn="key", operation="sign")
	gpgme.op_edit(key, KeyEditor("addkey").edit_fnc, out, out)
	subkey = check_key(address, whatreturn="key", operation="encrypt")
	key_to_mysql(key)
	return upload_key(subkey)

def delete_expired_subkey(address):
	global gpgme

	out = pyme.core.Data()
	key = check_key(address, whatreturn="key", operation="any", expired=True)
	if key:
		gpgme.op_edit(key, KeyEditor("delkey").edit_fnc, out, out)
		keyagain = check_key(address, whatreturn="key", operation="any", expired=True)
		if not keyagain:
			cur = BMMySQL().db.cursor()
			cur.execute ("INSERT INTO gpg (email, fingerprint, private, exp, data) VALUES (%s, %s, %s, FROM_UNIXTIME(%s), %s) ON DUPLICATE KEY UPDATE exp = VALUES(exp), data = VALUES(data)",
				(key.uids[0].email, key.subkeys[0].fpr, 0, key.subkeys[0].expires, public))
			rowcount += cur.rowcount
	# if changed but still exists, update
	# if not exists anymore, delete
			

def upload_key(key):
	global gpg
	uploaded = 0
	for server in BMConfig().get("pgpkeyservers"):
		server_url = BMConfig().get("pgpkeyservers", server, "url").split("/")[2]
		try:
			result = gpg.send_keys(server_url, key.subkeys[0].fpr)
			uploaded += 1
			logging.debug('Uploading PGP key to ' + server_url + ' : ' + str(result))
		except:
			logging.error('Uploading PGP key to ' + server_url + ' fail')
			
	return (uploaded > 0)

# create PGP key for user
def create_key(address):
	## generate key
	time_start = time.time()
	config = BMConfig()
	input_data = gpg.gen_key_input(name_email=address, name_real=address, name_comment='Generated by mailchuck.com', key_type="RSA", key_length=4096, expire_date=config.get("bmgateway", "pgp", "expire"))
	try:
		key = gpg.gen_key(input_data)
	except:
		return False
	time_stop = time.time()
	time_total = int(time_stop - time_start)
	logging.debug('Generated PGP key for ' + address + ' in ' + str(time_total) + ' seconds')

	## upload key
	keyid = check_key(address, whatreturn="keyid", operation="any")
	return (upload_key(keyid) > 0)


## lookup PGP key by email
def download_key(address):
	seen = {}
	imported = False
	for server in BMConfig().get("pgpkeyservers"):
		## try to grab key
		try:
			soup = BeautifulSoup(urllib2.urlopen(BMConfig().get("pgpkeyservers", server, "url") +
				BMConfig().get("pgpkeyservers", server, "begin") +
				urllib.quote(address) +
				BMConfig().get("pgpkeyservers", server, "end")).read())

			## extract key result
			key_url = ''
			for item in soup(text=re.compile(r'pub ')):
				for key_link in item.parent('a'):
					key_url = key_link.get('href')
					if key_url in seen:
						continue
					seen[key_url] = True
					key_url = BMConfig().get("pgpkeyservers", server, "url") + key_url
					key = ''
					try:
						key_soup = BeautifulSoup(urllib2.urlopen(key_url))
						key = key_soup.find('pre').getText()
						if not key:
							continue
						if import_key(key):
							imported = True
					except urllib2.URLError, e:
						if e == 'HTTP Error 404: Not found':
							continue
						else:
							logging.error('PGP keyfinder encountered an error when contacting the ' + server + ' keyserver: ' + str(e))
							continue
		## if there is an error
		except urllib2.URLError, e:
			
			## no key available, so return
			if e == 'HTTP Error 404: Not found':
				continue

			## something went wrong!
			else:
				logging.error('PGP keyfinder encountered an error when contacting the ' + server + ' keyserver: ' + str(e))
				continue
	return imported

## check if we have a GPG key in our keyring
def check_key(address, whatreturn="keyid", operation="any", expired=False):
	global gpgme
	#gpgme.op_keylist_start(address, 0)
	if BMConfig().get("bmgateway", "bmgateway", "outgoing_thread") == 0:
		key_from_mysql(address)
	#gpgme.set_keylist_mode(pyme.constants.KEYLIST_MODE_LOCAL | pyme.constants.KEYLIST_MODE_EXTERN)
	for i in range(0, 1):
		for key in gpgme.op_keylist_all(address, 0):
			if (key.expired and not expired) or key.disabled or key.revoked:
				continue
			# TODO differentiate signing and encryption
			for subkey in key.subkeys:
				if (not expired and not subkey.expired) and not subkey.disabled and not subkey.revoked and (operation == "any" or
					(operation == "encrypt" and subkey.can_encrypt) or (operation == "sign" and subkey.can_sign)):
					if whatreturn == "keyid":
						return subkey.keyid
					elif whatreturn == "fpr":
						return subkey.fpr
					elif whatreturn == "key":
						return key
					else:
						return subkey
		if i == 0 and address and not download_key(address):
			break
	return False

def verify(signed, msg_sender, msg_recipient, detached_sig = None):
	global gpgme
	plain = pyme.core.Data()
	cipher = pyme.core.Data(lib.unicode.to_string(signed))
	retval = signed

	check_key (msg_sender, whatreturn = "key", operation = "any")

	try:
		if detached_sig:
			gpgme.op_verify(pyme.core.Data(detached_sig), cipher, None)
		else:
			gpgme.op_verify(cipher, None, plain)
		if plain:
			plain.seek(0,0)
			retval = plain.read()
	except:
		logging.error("Signature verification of email destined for " + msg_recipient + " failed")
		return False, False
	return retval, verify_parse(msg_sender)

def verify_parse(msg_sender):
	global gpgme
	# signatures
	verifiedresult = gpgme.op_verify_result()
	verified = False
	index = 0
	for sign in verifiedresult.signatures:
		index += 1
		try:
			for uid in gpgme.get_key(sign.fpr, 0).uids:
				if uid.email.lower() == msg_sender and sign.status == 0:
					verified = True
		except:
			pass
#		print "signature", index, ":"
#		print "  summary:    ", sign.summary
#		print "  status:     ", sign.status
#		print "  timestamp:  ", sign.timestamp
#		print "  fingerprint:", sign.fpr
#		print "  email:      ", gpgme.get_key(sign.fpr, 0).uids[0].email.lower()
#		print "  uid:        ", gpgme.get_key(sign.fpr, 0).uids[0].uid
	return verified

def decrypt_content(encrypted, msg_sender, msg_recipient, multi = False):
	global gpgme
	plain = pyme.core.Data()
	cipher = pyme.core.Data(lib.unicode.to_string(encrypted))
	decrypted = ""
	decrypted_raw = ""
	detached_sig = None

	check_key (msg_sender, whatreturn = "key", operation = "any")

	try:
		gpgme.op_decrypt_verify(cipher, plain)
	except:
		logging.error("Decryption of email destined for " + msg_recipient + " failed")
		return False, False

	## convert to email message format
	plain.seek(0,0)
	
	## extract decrypted data
	if multi:
		decrypted_msg = email.message_from_string(plain.read())
		for decrypted_part in decrypted_msg.walk():
			if decrypted_part.get_content_type() == "text/plain":
				decrypted_str = decrypted_part.get_payload(decode=1)
				decrypted_raw += decrypted_part.as_string(False)
				if decrypted_part.get_content_charset():
					decrypted += decrypted_str.decode(decrypted_part.get_content_charset())
				else:
					decrypted += decrypted_str
			elif decrypted_part.get_content_type() == "application/pgp-signature":
				detached_sig = decrypted_part.get_payload(decode=1)
	else:
		decrypted = plain.read()

	if detached_sig:
		trash, sigverify = verify(decrypted_raw, msg_sender, msg_recipient, detached_sig)
		return decrypted, sigverify
	else:
		return decrypted, verify_parse(msg_sender)
