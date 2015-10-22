#!/usr/bin/python

## imports
import os
import re
import time
import datetime
import argparse
import logging
import signal
import sys
import threading
import xmlrpclib
import json
import smtplib
import base64
import email
import html2text
import lib.gpg
import lib.bmsignal
import lib.bmmega
#import lib.sendingtemplates
import lib.payment
import lib.milter
import Milter
from lib.config import BMConfig
from lib.mysql import BMMySQL
from lib.bmlogging import BMLogging
from lib.bmapi import BMAPI
from lib.sendbm import SendBMTemplate, SendBM
from lib.bmmessage import BMMessage
import lib.maintenance
import lib.user
import random
from subprocess import call

from BeautifulSoup import BeautifulSoup
from email.parser import Parser
from email.header import decode_header
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
from email import Charset
from email.generator import Generator

import chardet

try:
	import pyinotify
	have_inotify = True
except ImportError:
	have_inotify = False

import pprint

## setup logging
BMLogging()

## check if username is banned
def is_banned_username(username):
	if username in BMConfig().get("bmgateway", "banned_usernames"):
		return True
	else:
		return False

## read email from file
def read_email(k):
	try:
		f = open(BMConfig().get("bmgateway", "bmgateway", "mail_folder") + k, 'r')
		message = f.read()
		return message
	except IOError:
		logging.error('Could not read email: ' + BMConfig().get("bmgateway", "bmgateway", "mail_folder") + k)
		return


## delete email from file
def delete_email(k):
	try:
		os.remove(BMConfig().get("bmgateway", "bmgateway", "mail_folder") + k)
	except OSError:
		logging.error('Could not delete email: ' + BMConfig().get("bmgateway", "bmgateway", "mail_folder") + k)

## save email into another directory
def save_email(k):
	savedir = BMConfig().get("bmgateway", "bmgateway", "mail_folder") + "../cur/"
	try:
		os.rename(BMConfig().get("bmgateway", "bmgateway", "mail_folder") + k,
			savedir + k)
	except OSError:
		logging.error('Could not save email: ' + BMConfig().get("bmgateway", "bmgateway", "mail_folder") + k + " to " + savedir)


## generate a bitmessage address for an incoming email adress
def generate_sender_address(email):
	## generate random address
	time_start = time.time()
	address = BMAPI().conn().createRandomAddress(base64.b64encode(email))
	time_stop = time.time()
	time_total = int(time_stop - time_start)
	logging.info('Generated sender address for ' + email + ' in ' + str(time_total) + ' seconds')

	return address

## check for new bitmessages
def get_inbox():
	while True:
		try:
			messages = json.loads(BMAPI().conn().getAllInboxMessages())['inboxMessages']
		except:
			logging.warn('Could not read inbox messages via API %s. Retrying...', sys.exc_info()[0])
			time.sleep(random.random()+0.5)
			continue
		break
	return messages

def get_outbox():
	while True:
		try:
			messages = json.loads(BMAPI().conn().getAllSentMessages())['sentMessages']
		except:
			logging.warn('Could not read outbox messages via API %s. Retrying...', sys.exc_info()[0])
			time.sleep(random.random()+0.5)
			continue
		break
	return messages

## send outbound email
def send_email(recipient, sender, subject, body, bm_id, userdata = None):
	## open connection
	server = smtplib.SMTP('localhost')
	server.set_debuglevel(0)

	## build message
	msg = MIMEMultipart()
	msg['From'] = sender
	msg['To'] = recipient
	msg['Subject'] = subject

	## Signature
	if BMConfig().get("bmgateway", "bmgateway", "signature") is not None:
		body += "-- \n" + \
			BMConfig().get("bmgateway", "bmgateway", "signature") + \
			"\n"

	enc_body = None
	sender_key = None
	recipient_key = None
	sign = BMConfig().get("bmgateway", "pgp", "sign")
	encrypt = BMConfig().get("bmgateway", "pgp", "encrypt")

	if userdata:
		if userdata.expired():
			sign = False
			encrypt = False
		else:
			# only override if not expired and pgp allowed globally
			if sign:
				sign = (userdata.pgp == 1)
			if encrypt:
				encrypt = (userdata.pgp == 1)

	#TODO find out if already encrypted/signed

	## generate a signing key if we dont have one
	if sign:
		if not lib.gpg.check_key(sender, whatreturn="key", operation="sign"):
			lib.gpg.create_primary_key(sender)
		sender_key = lib.gpg.check_key(sender, whatreturn="key", operation="sign")
		if not sender_key:
			logging.error('Could not find or upload user\'s keyid: %s', sender)

	## search for recipient PGP key
	if encrypt:
#		if lib.gpg.find_key(recipient):
		recipient_key = lib.gpg.check_key(recipient, whatreturn="key", operation="encrypt")
		if not recipient_key:
			logging.info('Could not find recipient\'s keyid, not encrypting: %s', recipient)
		# make sure sender has an encryption key
		if not lib.gpg.check_key(sender, whatreturn="key", operation="encrypt"):
			if not lib.gpg.check_key(sender, whatreturn="key", operation="sign"):
				lib.gpg.create_primary_key(sender)
			lib.gpg.create_subkey(sender)

	if sender_key and recipient_key:
		enc_body = lib.gpg.encrypt_text(body, recipient_key, sender_key)
		logging.info('Encrypted and signed outbound mail from %s to %s', sender, recipient)
	elif recipient_key:
		enc_body = lib.gpg.encrypt_text(body, recipient_key)
		logging.info('Encrypted outbound mail from %s to %s', sender, recipient)
	elif sender_key and not recipient == BMConfig().get("bmgateway", "bmgateway", "bug_report_address_email"):
		logging.info('Signed outbound mail from %s to %s', sender, recipient)
		enc_body = lib.gpg.sign_text(body, sender_key)

	## only encrypt if the operation was successful
	if enc_body:
		body = enc_body

	text = body

	## encode as needed
	body = MIMEText(body, 'plain')

	## attach body with correct encoding
	msg.attach(body)
	text = msg.as_string()

	## send message
	try:
		status = server.sendmail(sender, recipient, text, [], ["NOTIFY=SUCCESS,FAILURE,DELAY", "ORCPT=rfc822;" + recipient])
   		logging.info('Sent email from %s to %s', sender, recipient) 
		BMMessage.deleteStatic(bm_id, folder = "inbox")
	## send failed
	
	except smtplib.SMTPException as e:
   		logging.error('Could not send email from %s to %s: %s', sender, recipient, e)
		server.quit()
		for rcpt in e.recipients:
			return e.recipients[rcpt]

	server.quit()
	return

## list known addresses
def list_addresses():
	## print all addresses 
	print "\n####################################\nInternal Address List\n####################################"
	for tmp_email in BMAPI().address_list:
		print tmp_email + "\t\t\t" + BMAPI().address_list[tmp_email]
	print ''
	
	print "\n####################################\nUser List\n####################################"
	lib.user.GWUser()
	print ""


def str_timestamp():
	return time.strftime("Generated at: %b %d %Y %H:%M:%S\r\n", time.gmtime())

## delete address
def delete_address(address):
	## try to delete and don't worry about if it actually goes through
	BMAPI().conn().deleteAddressBookEntry(address)
	BMAPI().conn().deleteAddress(address)
	lib.user.GWUser(bm = address).delete()

	if BMConfig().get("bmgateway", "bmgateway", "debug"):
		logging.debug('Deleted bitmessage address, ' + address)

def field_in_list(message, address_list,
		message_field, list_field):
	result = False
	try:
		if message[message_field] == address_list[BMConfig().get("bmgateway", "bmgateway", list_field)]:
			result = True
	except:
		result = False
	return result
 

## check for new bitmessages to process
def check_bminbox(intcond):
	global interrupted
	## get all messages
	#all_messages = json.loads(api['conn'].getAllInboxMessages())['inboxMessages']	
	
	logging.info("Entering BM inbox checker loop")
	intcond.acquire()
	while not interrupted:
		all_messages = get_inbox()
	
		## if no messages
		if not all_messages:
			try:
				intcond.wait(BMConfig().get("bmgateway", "bmgateway", "process_interval"))
			except KeyboardInterrupt:
				break
			continue
	
		## loop through messages to find unread
		for a_message in all_messages:
	
			## if already read, delete and break
			if a_message['read'] == 1:
				BMMessage.deleteStatic(a_message['msgid'])
				continue
	
			## if the message is unread, load it by ID to trigger the read flag
			message = json.loads(BMAPI().conn().getInboxMessageByID(a_message['msgid'], False))['inboxMessage'][0]
	
			## if a blank message was returned
			if not message:
				logging.error('API returned blank message when requesting a message by msgID')
				delete_bitmessage_inbox(bm_id)
				BMMessage.deleteStatic(a_message['msgid'])
				continue
	
			## find message ID
			bm_id = message['msgid']
	
			## check if receive address is a DEregistration request
			if field_in_list(message, BMAPI().address_list,
				'toAddress', 'deregistration_address_label'):
	
				## check if address is registered
				userdata = lib.user.GWUser(bm = message['fromAddress'])
	
				## if the sender is actually registered and wants to deregister
				if userdata.check():
					## process deregistration
					logging.info('Processed deregistration request for user ' + userdata.email)
					delete_address(message['fromAddress'])
	
					## send deregistration confirmation email
					SendBMTemplate(
						sender = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "deregistration_address_label")),
						recipient = message['fromAddress'],
						template = "deregistration-confirmed",
						addmaps = {
							'email': userdata.email
						})
	
				## bogus deregistration request
				else:
					logging.warn('Purged malicious deregistration bitmessage from ' + message['fromAddress'])
	
			elif field_in_list(message, BMAPI().address_list, 'toAddress', 'bug_report_address_label'):
				userdata = lib.user.GwUser(bm = message['fromAddress'])
				# if not, create a fake one
				# relay to ticket
	
			## check if receive address is a registration request
			elif field_in_list(message, BMAPI().address_list,
				'toAddress', 'registration_address_label'):

				userdata = lib.user.GWUser(bm = message['fromAddress'])

				if userdata.check(): # status, config, etc
					command = base64.b64decode(message['subject']).lower()
					if command == "config":
						logging.info('Config request from %s', message['fromAddress'])
						body = base64.b64decode(message['message'])
						data = {}
						for line in body.splitlines():
							option = re.search("(\S+)\s*:\s*(\S+)", line)
							if option is None:
								continue
							if option.group(1).lower() == "pgp":
								data['pgp'] = lib.user.GWUserData.pgp(option.group(2))
							elif option.group(1).lower() == "attachments":
								data['attachments'] = lib.user.GWUserData.zero_one(option.group(2))
							#elif option.group(1).lower() == "flags":
								#data['flags'] = lib.user.GWUserData.numeric(option.group(2))
							elif option.group(1).lower() == "archive":
								data['archive'] = lib.user.GWUserData.zero_one(option.group(2))
							elif option.group(1).lower() == "masterpubkey_btc":
								data['masterpubkey_btc'] = lib.user.GWUserData.public_seed(option.group(2))
								# reset offset unless set explicitly
								if data['masterpubkey_btc'] is not None and not 'offset_btc' in data:
									data['offset_btc'] = "0"
							elif option.group(1).lower() == "offset_btc":
								data['offset_btc'] = lib.user.GWUserData.numeric(option.group(2))
							elif option.group(1).lower() == "feeamount":
								data['feeamount'] = lib.user.GWUserData.numeric(option.group(2), 8)
							elif option.group(1).lower() == "feecurrency":
								data['feecurrency'] = lib.user.GWUserData.currency(option.group(2))
							else:
								pass
						if userdata.update(data):
							SendBMTemplate(
								sender = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "registration_address_label")),
								recipient = message['fromAddress'],
								template = "configchange",
								addmaps = {
								})
						else:
							SendBMTemplate(
								sender = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "registration_address_label")),
								recipient = message['fromAddress'],
								template = "confignochange",
								addmaps = {
								})
							pass
					elif command == "status" or command == "" or not command:
						logging.info('Status request from %s', message['fromAddress'])
						SendBMTemplate(
							sender = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "registration_address_label")),
							recipient = message['fromAddress'],
							template = "status",
							addmaps = {
								'email': userdata.email,
								'domain': userdata.domain,
								'active': "Yes" if userdata.active else "No",
								'cansend': "Yes" if userdata.cansend else "No",
								'cancharge': "Yes" if userdata.cancharge else "No",
								'caninvoice': "Yes" if userdata.caninvoice else "No",
								'pgp': "server" if userdata.pgp else "local",
								'attachments': "Yes" if userdata.attachments else "No",
								'expires': userdata.exp.strftime("%B %-d %Y"),
								'masterpubkey_btc': userdata.masterpubkey_btc if userdata.masterpubkey_btc else "N/A",
								'offset_btc': str(userdata.offset_btc) if userdata.masterpubkey_btc else "N/A",
								'feeamount': str(userdata.feeamount) if userdata.masterpubkey_btc else "N/A",
								'feecurrency': str(userdata.feecurrency) if userdata.masterpubkey_btc else "N/A",
								'archive': "Yes" if userdata.archive else "No",
								'flags': hex(userdata.flags),
								'aliases': ', '.join(userdata.aliases) if userdata.aliases else "None"
							})
					else:
						logging.info('Invalid command from %s', message['fromAddress'])
						SendBMTemplate(
							sender = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "registration_address_label")),
							recipient = message['fromAddress'],
							template = "command-invalid",
							addmaps = {
								'command': command,
								'email': userdata.email
							})
					
				else: # attempt to register new user
					## find requested username
					proposed_registration_user = base64.b64decode(message['subject']).lower()

					#full_registration_user = registration_user + '@' + BMConfig().get("bmgateway", "bmgateway", "domain_name")
					valid_one = re.match('^[\w]{4,20}$', proposed_registration_user) is not None
					valid_two =  re.match('^[\w]{4,20}@' + BMConfig().get("bmgateway", "bmgateway", "domain_name") + '$', proposed_registration_user) is not None
	
					# strip domain if they sent it during registration
					if valid_one:
						full_registration_user = proposed_registration_user.lower() + '@' + BMConfig().get("bmgateway", "bmgateway", "domain_name")
						registration_user = proposed_registration_user.lower()
					elif valid_two:
						full_registration_user = proposed_registration_user.lower()
						registration_user = proposed_registration_user.split('@')[0].lower()
					else:
						logging.info('Invalid email address in registration request for %s', proposed_registration_user)
						SendBMTemplate(
							sender = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "registration_address_label")),
							recipient = message['fromAddress'],
							template = "registration-invalid",
							addmaps = {
								'email': proposed_registration_user
							})
						BMMessage.deleteStatic(bm_id)
						continue
	
					## if username is valid check if it's available

					## check if address is already registered to a username or is banned
					if is_banned_username(registration_user):
						logging.info('Banned email address in registration request for %s', registration_user)
						SendBMTemplate(
							sender = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "registration_address_label")),
							recipient = message['fromAddress'],
							template = "registration-duplicate",
							addmaps = {
								'email': full_registration_user
							})
						BMMessage.deleteStatic(bm_id)
						continue
					elif lib.user.GWUser(email = full_registration_user).check():
						logging.info('Duplicate email address in registration request for %s', registration_user)
						SendBMTemplate(
							sender = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "registration_address_label")),
							recipient = message['fromAddress'],
							template = "registration-duplicate",
							addmaps = {
								'email': full_registration_user
							})
						BMMessage.deleteStatic(bm_id)
						continue
	
					logging.info('Received registration request for email address %s ', full_registration_user)
					lib.user.GWUser(empty = True).add(bm = message['fromAddress'], email = full_registration_user)
					SendBMTemplate(
						sender = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "registration_address_label")),
							recipient = message['fromAddress'],
							template = "registration-confirmed",
							addmaps = {
								'email': full_registration_user
							})
			## if sent to the generic recipient or sender address
			elif field_in_list(message, BMAPI().address_list,
				'toAddress', 'relay_address_label'):
	
				## if user is not registered, purge
				userdata = lib.user.GWUser(bm = message['fromAddress'])
				if not userdata.check():
					if BMConfig().get("bmgateway", "bmgateway", "allow_unregistered_senders"):
						bm_sender = message['fromAddress'] + '@' + BMConfig().get("bmgateway", "bmgateway", "domain_name")
					else:
						logging.warn('Purged bitmessage from non-registered user ' + message['fromAddress'])
						BMMessage.deleteStatic(bm_id)
						continue
	
				## if user is registered, find their username @ domain
				else:
					bm_sender = userdata.email

				## find outbound email address
				bm_receiver = re.findall(r'[\w\.\+-]+@[\w\.-]+\.[\w]+', base64.b64decode(message['subject']))
				if len(bm_receiver) > 0:
					bm_receiver = bm_receiver[0]
				
				## if there is no receiver mapping or the generic address didnt get a valid outbound email, deny it
				if not bm_receiver:
					# FIXME explain to sender what is whrong
					logging.warn('Received and purged bitmessage with unknown recipient (likely generic address and bad subject)')
					if BMConfig().get("bmgateway", "bmgateway", "respond_to_missing"):
						SendBMTemplate(
							sender = message['toAddress'],
							recipient = message['fromAddress'],
							template = "relay-missing-recipient",
							addmaps = {
								'email': userdata.email,
							})
					BMMessage.deleteStatic(bm_id)
					continue
	
				# expired or cannot send
				if (userdata.expired() or userdata.cansend == 0) and not \
					(bm_receiver == BMConfig().get("bmgateway", "bmgateway", "bug_report_address_email")): # can still contact bugreport
					btcaddress, amount = lib.payment.payment_exists_domain (BMConfig().get("bmgateway", "bmgateway", "domain_name"), userdata.bm)
				        # create new one
       					if btcaddress == False:
                				btcaddress, amount = lib.payment.create_invoice_domain (BMConfig().get("bmgateway", "bmgateway", "domain_name"), userdata.bm)

					SendBMTemplate(
						sender = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "registration_address_label")),
						recipient = message['fromAddress'],
						template = "accountexpired",
						addmaps = {
							'btcuri': lib.payment.create_payment_uri(btcaddress, 'BTC', amount,
								BMConfig().get("bmgateway", "bmgateway", "companyname"), 'User ' + userdata.bm + " / " + userdata.email + ' subscription'),
				                        'service': 'Subscription for ' + userdata.email + ' from ' + datetime.date.today().strftime("%B %-d %Y") +
								' until ' + userdata.exp.strftime("%B %-d %Y"),
							'email': userdata.email
						})
					logging.warn("User " + message['fromAddress'] + " notified of payment requirement")
					BMMessage.deleteStatic(bm_id)
					continue
	
				bm_subject = base64.b64decode(message['subject'])
	 
				## handle removal of embedded MAILCHUCK-FROM:: tag for replies
				bm_subject = bm_subject.replace('MAILCHUCK-FROM::' + bm_receiver + ' | ', '');
	
				## remove email address from subject
				if field_in_list(message, BMAPI().address_list, 'toAddress', 'relay_address_label'):
					bm_subject = bm_subject.replace(bm_receiver, '')	
	
				## get message contents
				bm_body = base64.b64decode(message['message'])	

				## pad with a newline, otherwise it may look ugly
				if bm_body[-1:] != '\n':
					bm_body += '\n'
	
				## send message and delete bitmessage, bitches
				if (float(userdata.lastrelay) + BMConfig().get("bmgateway", "bmgateway", "throttle") > time.time()):
					SendBMTemplate(
						sender = message['toAddress'],
						recipient = message['fromAddress'],
						template = "relay-throttle",
						addmaps = {
							'email': userdata.email,
							'throttledelta':  str(int((float(userdata.lastrelay) +
								BMConfig().get("bmgateway", "bmgateway", "throttle") - time.time() + 60)/60))
						})
					logging.warn('Throttled %s', message['fromAddress'])
					BMMessage.deleteStatic(bm_id)
					continue
				else:
					retval = send_email(bm_receiver, bm_sender, bm_subject, bm_body, bm_id, userdata = userdata)
					if retval is None:
						logging.info('Relayed from %s to %s', message['fromAddress'], bm_receiver)
					else:
						if retval[0] >= 400 and retval[0] < 500:
							# do not delete, repeatable
							continue
						else:
							SendBMTemplate(
								sender = message['toAddress'],
								recipient = message['fromAddress'],
								template = "smtperror",
								addmaps = {
									'emailrcpt': bm_receiver,
									'errcode': retval[0],
									'errmessage': retval[1]
								}
							)
							

			## remove message
			BMMessage.deleteStatic(bm_id)
		intcond.wait(BMConfig().get("bmgateway", "bmgateway", "process_interval"))
	intcond.release()
	logging.info("Leaving BM inbox checker loop")
		
def check_bmoutbox(intcond):
	global interrupted
	## get all messages
	#all_messages = json.loads(api['conn'].getAllInboxMessages())['inboxMessages']	
	logging.info("Entering BM outbox checker loop")
	intcond.acquire()
	while not interrupted:
		all_messages = get_outbox()

		logging.info("Trashing old outbox messages")
		## if no messages
		if not all_messages:
			try:
				intcond.wait(BMConfig().get("bmgateway", "bmgateway", "outbox_process_interval"))
			except KeyboardInterrupt:
				break
			continue

		## loop through messages to find unread
		for a_message in all_messages:
			if a_message['status'] == 'ackreceived':
				userdata = lib.user.GWUser(bm = a_message['toAddress'])
				if userdata:
					userdata.setlastackreceived(a_message['lastActionTime'])
				BMMessage.deleteStatic(a_message['msgid'], folder = "outbox")

		logging.info("Vacuuming DB")
		result = BMAPI().conn().deleteAndVacuum()

		intcond.wait(BMConfig().get("bmgateway", "bmgateway", "outbox_process_interval"))
	intcond.release()
	logging.info("Leaving BM outbox checker loop")

def check_boxes():
	check_bminbox()
	check_bmoutbox()

def handle_email(k):
	global address_list
	userdata = None

	## read email from file
	msg_raw = read_email(k)
	if not msg_raw:
		logging.error('Could not open email file: ' + k)
		return


	## extract header
	msg_headers = Parser().parsestr(msg_raw)

	## check if email was valid
	if not msg_headers:
		logging.error('Malformed email detected and purged')
		delete_email(k)
		return

	## find email source and dest addresses
	msg_sender    = msg_headers["From"]

	## failed delivery email
	if msg_sender == '<>' or not msg_sender:
		msg_sender = BMConfig().get("bmgateway", "bmgateway", "relay_address_label")
	else:
		try:
			msg_sender    = re.findall(r'[\w\.+-]+@[\w\.-]+.[\w]+', msg_sender)[0]
		except:
			pass
	msg_sender = msg_sender.lower()

	msg_recipient = ""

	## find email details
	if msg_headers["To"]:
		rcpts = re.findall(r'[\w\.+-]+@[\w\.-]+.[\w]+', msg_headers["To"])
		if len(rcpts) > 0:
			msg_recipient = rcpts[0]
			## strip extension (user+foo@domain)
			msg_recipient = re.sub(r'\+.*@', '@', msg_recipient) 
			msg_recipient = msg_recipient.lower()
			userdata = lib.user.GWUser(email = msg_recipient, unalias = True)

	## check if we have a recipient address for the receiving email
	if not userdata.check():
		## look for X-Original-To instead
		rcpts = re.findall(r'[\w\.+-]+@[\w\.-]+.[\w]+', msg_headers["X-Original-To"])
		if len(rcpts) > 0:
			msg_recipient = rcpts[0]
			msg_recipient = re.sub(r'\+.*@', '@', msg_recipient) 
			msg_recipient = msg_recipient.lower()
			userdata = lib.user.GWUser(email = msg_recipient, unalias = True)

	## no valid recipient
	#if not msg_recipient in addressbook:
	#	logging.warn('Purged email destined for unknown user ' + msg_recipient + ' from ' + msg_sender)
	#	logging.debug(msg_headers)
	#	delete_email(k)
	#	return

	## check if we have valid sender and recipient details
	if not msg_sender or not msg_recipient:
		logging.warn('Malformed email detected and purged')
		delete_email(k)
		return

	## set bitmessage destination address
	bm_to_address = userdata.bm

	## set from address
	## check to see if we need to generate a sending address for the source email address
	# if not msg_sender in address_list:
	# 	bm_from_address = generate_sender_address(msg_sender)
	# 	address_list[msg_sender] = bm_from_address
	# else:
	bm_from_address = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "relay_address_label"))

	## find message subject
	msg_subject = decode_header(msg_headers['subject'])[0]
	if(msg_subject[1]):
		msg_subject = unicode(msg_subject[0], msg_subject[1])
	else:
		msg_subject = msg_subject[0]

	## find message body contents in plaintext
	msg_tmp = email.message_from_string(msg_raw)

	# handle DSN
	if msg_tmp.get_content_type() == "multipart/report" and msg_tmp.get_param("report-type", "") == "delivery-status" and msg_tmp.get("Auto-Submitted", "") == "auto-replied":
		for part in msg_tmp.walk():
			if part and part.get_content_type() == 'message/delivery-status':
				part_str = part.get_payload(decode = 0)
				for subpart in part_str:
					if subpart.get("Action", "") in ("relayed", "delivered", "expanded"):
						logging.info ("Successful DSN from " + bm_to_address)
						lib.user.GWUser(bm = bm_to_address).setlastrelay(lastrelay = time.time())
						delete_email(k)
						return

	msg_body = ''
	body_raw = ''
	decrypt_ok = False
	sigverify_ok = False
	mega_fileids = []

	# DKIM
	ar = msg_tmp.get_param("dkim", "missing", "Authentication-Results")
	if ar == "missing":
		try:
			domain = msg_sender.split("@")[-1]
			if lib.user.GWDomain(domain).check() and domain == msg_tmp.get_param("d", "missing", "DKIM-Signature"):
				ar = "pass" # we trust MTA to reject fakes
		except:
			pass

	## inline PGP
	for part in msg_tmp.walk():
		if part and part.get_content_type() == 'text/plain' and not (part.has_key("Content-Disposition") and part.__getitem__("Content-Disposition")[:11] == "attachment;"):
			part_str = part.get_payload(decode=1)
			if userdata.pgp == 1:
				if userdata.flags & 1 == 1:
					pgpparts = part_str.split("-----")
					# hack for absent pgp
					if not pgpparts or len(pgpparts) < 4:
						if part.get_content_charset():
							msg_body += part_str.decode(part.get_content_charset())
						else:
							charset = chardet.detect(part_str)
							if charset['encoding']:
								msg_body += part_str.decode(charset['encoding'])
							else:
								msg_body += part_str.decode('ascii')
						continue
					state = 0
					pgp_body = ""
					for pgppart in pgpparts:
						if pgppart == "BEGIN PGP MESSAGE":
							pgp_body = "-----" + pgppart + "-----"
							state = 1
						elif pgppart == "END PGP MESSAGE":
							pgp_body += "-----" + pgppart + "-----"
							# import from sql if necessary
							lib.gpg.check_key(msg_recipient)
							decrypted, sigverify_ok = lib.gpg.decrypt_content(pgp_body, msg_sender, msg_recipient)
							if isinstance(decrypted, basestring):
								part_str = decrypted
								decrypt_ok = True
							#else:
								#part_str = part.get_payload(decode = 0)
							sigresult = "fail"
							if sigverify_ok:
								sigresult = "ok"
							logging.info("Decrypted email from " + msg_sender + " to " + msg_recipient + ", signature: " + sigresult)
							state = 0
						elif pgppart == "BEGIN PGP SIGNED MESSAGE":
							pgp_body += "-----" + pgppart + "-----"
							state = 2
						elif pgppart == "BEGIN PGP SIGNATURE":
							pgp_body += "-----" + pgppart + "-----"
							state = 3
						elif pgppart == "END PGP SIGNATURE":
							pgp_body += "-----" + pgppart + "-----"
							# import from sql if necessary
							lib.gpg.check_key(msg_recipient)
							plain, sigverify_ok = lib.gpg.verify(pgp_body, msg_sender, msg_recipient)
							if isinstance(plain, basestring):
								part_str = plain
							#else:
								#part_str = part.get_payload(decode = 0)
							sigresult = "fail"
							if sigverify_ok:
								sigresult = "ok"
							logging.info("Verifying PGP signature from " + msg_sender + " to " + msg_recipient + ": " + sigresult)
							state = 0
						elif state == 0:
							if part.get_content_charset():
								msg_body += pgppart.decode(part.get_content_charset())
							else:
								charset = chardet.detect(pgppart)
								if charset['encoding']:
									msg_body += pgppart.decode(charset['encoding'])
								else:
									msg_body += pgppart.decode('ascii')
						elif state > 0:
							pgp_body += pgppart
				else:
					if "BEGIN PGP MESSAGE" in part_str:
						# import from sql if necessary
						lib.gpg.check_key(msg_recipient)
						decrypted, sigverify_ok = lib.gpg.decrypt_content(part_str, msg_sender, msg_recipient)
						if isinstance(decrypted, basestring):
							part_str = decrypted
							decrypt_ok = True
						else:
							part_str = part.get_payload(decode = 0)
						logging.info("Decrypted email from " + msg_sender + " to " + msg_recipient)
					elif "BEGIN PGP SIGNED MESSAGE" in part_str:
						# import from sql if necessary
						lib.gpg.check_key(msg_recipient)
						plain, sigverify_ok = lib.gpg.verify(part_str, msg_sender, msg_recipient)
						if isinstance(plain, basestring):
							part_str = plain
						else:
							part_str = part.get_payload(decode = 0)
			# PGP END
			
			body_raw += part.as_string(False)
			#print part.get_content_charset()
			#print msg_tmp.get_charset()
			if part.get_content_charset():
				try:
					part_str = part_str.decode(part.get_content_charset())
				except:
					charset = chardet.detect(part_str)
					part_str = part_str.decode(charset['encoding'])
			msg_body += part_str
	
	## if there's no plaintext content, convert the html
	if not msg_body:
		for part in msg_tmp.walk():
			if part and part.get_content_type() == 'text/html' and not (part.has_key("Content-Disposition") and part.__getitem__("Content-Disposition")[:11] == "attachment;"):
				part_str = part.get_payload(decode=1)
				h = html2text.HTML2Text()
				h.inline_links = False
				if part.get_content_charset():
					msg_body += h.handle(part_str.decode(part.get_content_charset()))
				else:
					charset = chardet.detect(part_str)
					msg_body += h.handle(part_str.decode(charset['encoding']))
				#msg_body = msg_body + html2text.html2text(unicode(part.get_payload(), part.get_content_charset()))		
	
	## if there's no plaintext or html, check if it's encrypted
	# PGP/MIME
	has_encrypted_parts = False
	if not msg_body:
		for part in msg_tmp.walk():
			if part.get_content_type() == 'application/pgp-encrypted':
				has_encrypted_parts = True
				# import from sql if necessary
				if userdata.pgp == 1:
					lib.gpg.check_key(msg_recipient)

			## look for encrypted attachment containing text
			if part.get_content_type() == 'application/octet-stream' and has_encrypted_parts:
				part_str = part.get_payload(decode=1)

				if userdata.pgp == 0:
					msg_body += part_str
					continue

				## if we see the pgp header, decrypt
				if 'BEGIN PGP MESSAGE' in part_str:
					decrypted_data, sigverify_ok = lib.gpg.decrypt_content(part_str, msg_sender, msg_recipient, True)

					## decrypt failed
					if not decrypted_data:
						logging.error("Decryption of email destined for " + msg_recipient + " failed")
						msg_body += part.get_payload(decode=0)
						continue

					logging.info("Decrypted email from " + msg_sender + " to " + msg_recipient)
					msg_body += decrypted_data
					decrypt_ok = True
				elif "BEGIN PGP SIGNED MESSAGE" in part_str:
					plain, sigverify_ok = lib.gpg.verify(part_str, msg_sender, msg_recipient)
					if isinstance(plain, basestring):
						msg_body += plain
					else:
						msg_body += part.get_payload(decode = 0)
				
				## unknown attachment
				else:
					logging.debug("Received application/octet-stream type in inbound email, but did not see encryption header")

	if not sigverify_ok:
		for part in msg_tmp.walk():
			if part.get_content_type() == 'application/pgp-signature':

				if userdata.pgp == 0:
					msg_body = '-----BEGIN PGP SIGNED MESSAGE-----\n' + msg_body
					msg_body += '\n-----BEGIN PGP SIGNATURE-----\n'
					msg_body += part.get_payload(decode=1)
					msg_body += '\n-----END PGP SIGNATURE-----\n'
					continue

				# import from sql if necessary
				lib.gpg.check_key(msg_recipient)
				plain, sigverify_ok = lib.gpg.verify(body_raw, msg_sender, msg_recipient, part.get_payload(decode=1))

	if userdata.attachments == 1 and not userdata.expired():
		for part in msg_tmp.walk():
			if part.has_key("Content-Disposition") and part.__getitem__("Content-Disposition")[:11] == "attachment;":
				# fix encoding
				try:
					filename = email.header.decode_header(part.get_filename())
					encoding = filename[0][1]
					filename = filename[0][0]
				except:
					filename = part.get_filename()
					encoding = False

				fileid, link = lib.bmmega.mega_upload(userdata.bm, filename, part.get_payload(decode = 1))
				mega_fileids.append(fileid)
				if encoding:
					filename = unicode(filename, encoding)
				logging.info("Attachment \"%s\" (%s)", filename, part.get_content_type())
				msg_body = "Attachment \"" + filename + "\" (" + part.get_content_type() + "): " + link + "\n" + msg_body
	if userdata.pgp == 1:
		if not decrypt_ok:
			msg_body = "WARNING: PGP encryption missing or invalid. The message content could be exposed to third parties.\n" + msg_body
		if not sigverify_ok:
			msg_body = "WARNING: PGP signature missing or invalid. The authenticity of the message could not be verified.\n" + msg_body
	else:
		# msg_body = "WARNING: Server-side PGP is off, passing message as it is.\n" + msg_body
		pass
		
	if not ar[0:4] == "pass":
		msg_body = "WARNING: DKIM signature missing or invalid. The email may not have been sent through legitimate servers.\n" + msg_body

	logging.info('Incoming email from %s to %s', msg_sender, msg_recipient)

	sent = SendBM(bm_from_address, bm_to_address,
		'MAILCHUCK-FROM::' + msg_sender + ' | ' + msg_subject.encode('utf-8'),
		msg_body.encode('utf-8'))
	if sent.status:
		for fileid in mega_fileids:
			# cur.execute ("UPDATE mega SET ackdata = %s WHERE fileid = %s AND ackdata IS NULL", (ackdata.decode("hex"), fileid))
			pass
		## remove email file
		if userdata.archive == 1:
			#print msg_body
			save_email(k)
		else:
			delete_email(k)

class InotifyEventHandler(pyinotify.ProcessEvent):
	def process_default(self, event):
		if (os.path.isfile(event.pathname)):
			# to avoid crashes from taking down the whole processing, in the future for parallel processing
			email_thread = threading.Thread(target=handle_email, name='EmailIn', args=(event.name,))
			email_thread.start()
			#email_thread.join()

def inotify_incoming_emails():
	dir = BMConfig().get("bmgateway", "bmgateway", "mail_folder")
	check_emails(None)

	wm = pyinotify.WatchManager()
	notifier = pyinotify.ThreadedNotifier(wm, InotifyEventHandler())
	notifier.setName ("Inotify")
	wm.add_watch (dir, pyinotify.IN_CREATE|pyinotify.IN_CLOSE_WRITE|pyinotify.IN_MOVED_TO)
	#wm.add_watch (dir, pyinotify.ALL_EVENTS, rec=True)
	return notifier

## check for new mail to process
def check_emails(intcond):
	## find new messages in folders
	dir = os.listdir(BMConfig().get("bmgateway", "bmgateway", "mail_folder"))

	## no new mail
	if not dir:
		return

	## iterate through new messages, each in thread so that crashes do not prevent continuing
	for k in dir:
		email_thread = threading.Thread(target=handle_email, name="EmailIn", args=(k,))
		email_thread.start()
		email_thread.join()

if not BMMySQL().connect():
	print "Failed to connect to mysql"
	sys.exit()

lib.gpg.gpg_init()

## main  
parser = argparse.ArgumentParser(description='An email <-> bitmessage gateway.')
parser.add_argument('-l','--list', help='List known internal and external addresses',required=False, action='store_true')
parser.add_argument('-d','--delete', help='Delete an address',required=False, default=False)
parser.add_argument('-a','--add', help='Generate a new bitmessage address with given label',required=False, default=False)

args = parser.parse_args()

## call correct function
if args.list == True:
	list_addresses()

elif args.delete:
	delete_address(args.delete)	

elif args.add:
	generate_sender_address(args.add)

else:
	while BMAPI().conn() is False:
		print "Failure connecting to API, sleeping..."
		time.sleep(random.random()+0.5)

	milter_thread = threading.Thread()
	maintenance_thread = threading.Thread()
	email_thread = threading.Thread()
	bminbox_thread = threading.Thread()
	bmoutbox_thread = threading.Thread()

	interrupted = False
	intcond = threading.Condition()

	outboxlast = 0

	logging.info("Starting BM gateway")

	## run managers in threads
	while not interrupted:
		if BMConfig().get("bmgateway", "bmgateway", "incoming_thread") and not email_thread.isAlive():
			if email_thread.ident is not None:
				email_thread.join()
			if have_inotify:
				email_thread = inotify_incoming_emails()
			else:
				email_thread = threading.Thread(target=check_emails, name="EmailIn", args=(intcond,))
			email_thread.start()
		if BMConfig().get("bmgateway", "bmgateway", "outgoing_thread"):
			if not bminbox_thread.isAlive():
				if bminbox_thread.ident is not None:
					bminbox_thread.join()
				bminbox_thread = threading.Thread(target=check_bminbox, name="BMIn", args=(intcond,))
				bminbox_thread.start()

			if time.time() - outboxlast > BMConfig().get("bmgateway", "bmgateway", "outbox_process_interval") and not bmoutbox_thread.isAlive():
			#if not bmoutbox_thread.isAlive():
				if bmoutbox_thread.ident is not None:
					bmoutbox_thread.join()
				outboxlast = time.time()
				bmoutbox_thread = threading.Thread(target=check_bmoutbox, name="BMOut", args=(intcond,))
				bmoutbox_thread.start()

		if BMConfig().get("bmgateway", "bmgateway", "milter_thread") and not milter_thread.isAlive():
			if milter_thread.ident is not None:
				milter_thread.join()
			milter_thread = threading.Thread(target=lib.milter.run, name="Milter")
			milter_thread.start()

		if BMConfig().get("bmgateway", "bmgateway", "maintenance_thread") and not maintenance_thread.isAlive():
			if maintenance_thread.ident is not None:
				maintenance_thread.join()
			maintenance_thread = threading.Thread(target=lib.maintenance.serve, name="Maintenance")
			maintenance_thread.start()


		try:
			time.sleep(BMConfig().get("bmgateway", "bmgateway", "process_interval"))
		except KeyboardInterrupt:
			interrupted = True

	logging.info("Shutting down BM gateway")
	print "Shutting down BM gateway, please wait a couple of seconds ..."

	intcond.acquire()
	intcond.notifyAll()
	intcond.release()

	if BMConfig().get("bmgateway", "bmgateway", "incoming_thread"):
		if have_inotify and email_thread.isAlive:
			email_thread.stop()
		email_thread.join()

	if BMConfig().get("bmgateway", "bmgateway", "outgoing_thread"):
		bminbox_thread.join()
		if bmoutbox_thread.ident is not None:
			bmoutbox_thread.join()

	if BMConfig().get("bmgateway", "bmgateway", "maintenance_thread"):
		if maintenance_thread.isAlive:
			maintenance_thread.stop()
		maintenance_thread.join()

	if BMConfig().get("bmgateway", "bmgateway", "milter_thread") and milter_thread.isAlive():
		#milter_thread.stop()
		try:
			Milter.stop()
		except:
			pass
		milter_thread.join()

	logging.info("Stopped BM gateway")
