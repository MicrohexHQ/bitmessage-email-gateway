#!/bin/env python
 
from smtpd import SMTPChannel, SMTPServer
 
class LMTPChannel(SMTPChannel):
	# LMTP "LHLO" command is routed to the SMTP/ESMTP command
	def smtp_LHLO(self, arg):
		self.smtp_HELO(arg)

	def smtp_RCPT(self, arg):
		print >> DEBUGSTREAM, '===> RCPT', arg
		if not self.__mailfrom:
			self.push('503 Error: need MAIL command')
			return
		address = self.__getaddr('TO:', arg) if arg else None
		if not address:
			self.push('501 Syntax: RCPT TO: <address>')
			return
		### Check for a valid mailbox
		if not address in VALID_ADDRESSES:
			self.push("550 No such user here")
			return
		self.__rcpttos.append(address)
		print >> DEBUGSTREAM, 'recips:', self.__rcpttos
		self.push('250 Ok')
 
class LMTPServer(SMTPServer):
	def __init__(self, localaddr, remoteaddr):
		SMTPServer.__init__(self, localaddr, remoteaddr)
 
	def process_message(self, peer, mailfrom, rcpttos, data):
		print 'Receiving message from:', peer
		print 'Message addressed from:', mailfrom
		#rcpttos is a list
		print 'Message addressed to  :', rcpttos
		print 'Message length        :', len(data)
		print 'Message               :', data
		return
 
	def handle_accept(self):
		conn, addr = self.accept()
		channel = LMTPChannel(self, conn, addr)


