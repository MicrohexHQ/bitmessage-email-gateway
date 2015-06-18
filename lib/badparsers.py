#!/usr/bin/python2.7

import email
import logging
import lib.payment
import os.path
from lib.config import BMConfig
import logging
import chardet
#from lib.user import BMUser
import email

class EmailParser(object):
	def __init__ (self):
		self.raw = None
		self.body = None
		self.subject = None
		self.sender = None
		self.recipient = None
		self.recipientbm = None
		self.pgpbody = None
		self.headers = {}
		self.signature = False
		self.encryption = False
		self.dkim = False
		self.status = False
		self.multipart = False
		self.maintype = None
		self.subtype = None
		self.charset = None
		self.attachment = None
		self.dsn = None
		self.parent = None
		self.out = None

	def parse(self):
		if self.parent == None:
			try:
				self.parse_headers()
			except:
				return False
		try:
			self.parse_body()
		except:
			return False

		self.subject = base64.b64encode(subject)
		self.body = base64.b64encode(body)
		if (sender[0:3] == "BM-"):
			senderbm = sender
		else:
			senderbm = BMAPI().get_address(sender)
		recipientbm = recipient
		userdata = lib.user.GWUser(bm = recipient)
		if userdata.check():
			recipient = userdata['email']
		try:
			ackData = BMAPI().conn().sendMessage(recipientbm, senderbm, self.subject, self.body, 2)
			logging.info("Sent BM from %s to %s", sender, recipient)
		except:
			logging.error("Failure sending BM from %s to %s", sender, recipient)
			return False
		return True

	def read_from_file(self, fname):
		try:
			fullpath = os.path.join(BMConfig().get("bmgateway", "bmgateway", "mail_folder"), fname)
			f = open(fullpath, 'r')
			self.raw = f.read()
			f.close()
		except IOError:
			logging.error('Could not read email from: ' + fullpath)

	def from_data(self, data):
		self.raw = data

	def parse_headers(self):
		self.headers = email.parser.Parser().parsestr(self.raw)
		if not self.headers:
			logging.error('Email missing headers')
			raise
		self.extract_sender()
		self.extract_recipient()
		if not self.sender or not self.recipient:
			logging.warn('Email missing sender or recipient')
			raise
		self.extract_subject()
		self.extract_dkim()

	def extract_sender(self):
		self.sender = self.headers["From"]

		## DSN or missing sender
		if self.sender == '<>' or not self.sender:
			self.sender = BMConfig().get("bmgateway", "bmgateway", "relay_address_label")
		else:
			self.sender = re.findall(r'[\w\.+-]+@[\w\.-]+.[\w]+', self.sender)[0]
		self.sender = self.sender.lower()

		self.body = email.message_from_string(self.raw)

		if self.body.get_content_maintype == "multipart":
			self.multipart = True
			self.maintype = self.body.get_content_maintype()
			self.subtype = self.body.get_content_subtype()
		self.charset = self.body.get_content_charset()

	def attachment(

		if self.body.has_key("Content-Disposition") and self.body.__getitem__("Content-Disposition")[:11] == "attachment":
			self.attachment = email.header.decode_header(part.get_filename())[0]
			
	def extract_recipient(self):
		## find email details
		userdata = None
		rcpts = ()
		for rcpthdr in ("To", "X-Original-To", "Cc"):
			rcpts.extend(re.findall(r'[\w\.+-]+@[\w\.-]+.[\w]+', self.headers[rcpthdr]))
		for candidate in rcpts:
			## strip extension (user+foo@domain)
			self.recipient = re.sub(r'\+.*@', '@', candidate) 
			## lowercasse
			self.recipient = self.recipient.lower()
			## check if user exists
			userdata = lib.user.GWUser(email = self.recipient, unalias = True)
			if userdata.check():
				break

	def extract_subject(self):
		self.subject = email.header.decode_header(self.headers['Subject'])[0]
		if(self.subject[1]):
			self.subject = unicode(self.subject[0], self.subject[1])
		else:
			self.subject = self.subject[0]

	def extract_dkim(self):
		ar = self.body.get_param("dkim", "missing", "Authentication-Results")
		if ar == "missing":
			domain = self.sender.split("@")[-1]
			if lib.user.GWDomain(domain).check() and domain == self.body.get_param("d", "missing", "DKIM-Signature"):
				ar = "pass" # we trust MTA to reject fakes from domains that hare handled locally
		if ar[0:4] == "pass":
			self.dkim = True
	
	def parse_body(self)
		cipher = None
		signature = None
		if self.multipart:
			for part in self.body.walk():
				if part.get_content_type() == 'message/delivery-status':
					part_str = part.get_payload(decode = 0)
					for subpart in part_str:
						if subpart.get("Action", "") in ("relayed", "delivered", "expanded") and
							self.body.get_param("report-type", "") == "delivery-status" and self.body.get("Auto-Submitted", "") == "auto-replied":
							self.dsn = True
				elif part.get_content_type() == 'text/plain' and
					(self.subtype != "alternative" or self.out == None): # lower precedence if other content exists
					self.handle_text(part)
				elif part.get_content_type() == 'message/rfc822':
					self.handle_text(part)
				elif part.get_content_type() == 'text/html':
					self.handle_html(part)
				elif part.has_key("Content-Disposition") and part.__getitem__("Content-Disposition")[:11] == "attachment;":
					if has setting
						handle_attachment()
					
			elif self.subtype == "mixed":
			elif self.subtype == "digest":
			elif self.subtype == "alternative":
			elif self.subtype == "related":
			elif self.subtype == "signed":
			elif self.subtype == "encrypted":
		elif self.maintype == "message" and self.subtype == "rfc822":
			self.handle_text(self.body)
		elif self.maintype == "text" and self.subtype == "plain":
			self.handle_text(self.body)
		elif self.maintype == "text" and self.subtype == "html":
			self.handle_html(part)
		return True

	def handle_text(self, msg):
		text = msg.get_payload(decode = True)
		if (self.has_pgp(text)):
			self.out += self.handle_pgp(msg)
		else:
			self.out += text

	def handle_html(self, msg):
		text = msg.get_payload(decode = True)
		if (self.has_pgp(text)):
			text = self.handle_pgp(text)
		h = html2text.HTML2Text()
		h.inline_links = False
		if not msg.get_content_charset():
			charset = chardet.detect(text)
			if charset['encoding'] == None:
				charset = 'ascii'
			else:
				charset = charset['encoding']

		text = h.handle(text).decode(charset))
		self.out += text

	def has_pgp(self, msg):
		if "-----BEGIN PGP SIGNED MESSAGE-----" in text or "-----BEGIN PGP MESSAGE-----" in text:
			return True
		return False

	def handle_pgp(self, msg):
		text = msg.get_payload(decode = True).decode(charset)
		pgpparts = text.split("-----")
		state = 0
		pgp_body = ""
		out = ""
		for pgppart in pgpparts:
			if pgppart == "BEGIN PGP MESSAGE":
				pgp_body = "-----" + pgppart + "-----"
				state = 1
			elif pgppart == "END PGP MESSAGE":
				pgp_body += "-----" + pgppart + "-----"
				decrypted, sigverify_ok = lib.gpg.decrypt_content(pgp_body, self.sender, self.recipient)
				self.encryption = False
				if isinstance(decrypted, basestring):
					out += decrypted
					self.encryption = True
				else:
					out += pgp_body
				self.signature = False
				if sigverify_ok:
					self.signature = True
				logging.info("Decryption email from %s to %s: %s, signature: %s", self.sender, self.recipient,
					("ok" if self.encryption else "fail"), ("ok" if self.signature else "fail"))
				state = 0
			elif pgppart == "BEGIN PGP SIGNED MESSAGE":
				pgp_body += "-----" + pgppart + "-----"
				state = 2
			elif pgppart == "BEGIN PGP SIGNATURE":
				pgp_body += "-----" + pgppart + "-----"
				state = 3
			elif pgppart == "END PGP SIGNATURE":
				pgp_body += "-----" + pgppart + "-----"
				plain, sigverify_ok = lib.gpg.verify(pgp_body, self.sender, self.recipient)
				if isinstance(plain, basestring):
					out += plain
				else:
					part_str += pgp_body
				self.signature = False
				if sigverify_ok:
					self.signature = True
				logging.info("Verifying PGP signature from %s to %s: %s", self.sender, self.recipient,
					("ok" if self.signature else "fail"))
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
		return out


class BMParser(object):
