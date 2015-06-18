#!/usr/bin/python2.7

import urlparse
import os
import email
import time
import lib.payment
import string
import logging
import re
from lib.config import BMConfig
from lib.bmapi import BMAPI

class MsgTemplate(object):
	subject = None
	body = None
	def __init__(self, maps, base):
		# load template source
		src = None
		try:
			with open(os.path.join(os.path.dirname(__file__), '..', 'templates',  base + '.txt')) as tempsrc:
				src = email.message_from_file(tempsrc)
		except:
			return None

		# init general maps
		maps['timestamp'] = time.strftime("Generated at: %b %d %Y %H:%M:%S GMT", time.gmtime())
		maps['domain'] = BMConfig().get("bmgateway", "bmgateway", "domain_name")
		maps['relayaddress'] = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "relay_address_label"))
		maps['deregisteraddress'] = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "deregistration_address_label"))
		maps['registeraddress'] = BMAPI().get_address(BMConfig().get("bmgateway", "bmgateway", "registration_address_label"))
		maps['bugreportemail'] = BMConfig().get("bmgateway", "bmgateway", "bug_report_address_email")
		maps['bugreportaddress'] = BMConfig().get("bmgateway", "bmgateway", "bug_report_address_bitmessage")
		maps['mailinglistaddress'] = BMConfig().get("bmgateway", "bmgateway", "broadcast_address_bitmesage")
		maps['companyname'] = BMConfig().get("bmgateway", "bmgateway", "companyname")
		maps['companyaddress'] = BMConfig().get("bmgateway", "bmgateway", "companyaddress")

		# BTC URI
		if 'btcuri' in maps:
			addr = re.search('^bitcoin:([^?]+)(\?(.*))?', maps['btcuri'])
			if addr:
				maps['btcaddress'] = addr.group(1)
				attr = urlparse.parse_qs(addr.group(3))
				if 'amount' in attr:
					maps['btcamount'] = attr['amount'][0]
			maps['qrbtcuri'] = lib.payment.qrcode_encoded(maps['btcuri'])

		subst = string.Template(src.get_payload()).safe_substitute(maps)
		self.body = subst.replace('\n', '\r\n')

		if src.has_key("Subject"):
			self.subject = string.Template(src.get("Subject")).safe_substitute(maps)
		#return self

	def getsubject(self):
		return self.subject

	def getbody(self):
		return self.body
