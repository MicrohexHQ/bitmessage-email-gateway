#!/usr/bin/python2.7

import SocketServer
import xmlrpclib
import base64
import lib.netstring
import json
import pprint
from lib.config import BMConfig

class MyTCPHandler(SocketServer.BaseRequestHandler):
	"""
	The RequestHandler class for our server.

	It is instantiated once per connection to the server, and must
	override the handle() method to implement communication to the
	client.
	"""

	def handle(self):
		# self.request is the TCP socket connected to the client
		api = xmlrpclib.ServerProxy('http://' + BMConfig().get("bmapi", "bm1", "username") + ':' + 
			BMConfig().get("bmapi", "bm1", "password") + '@' + 
			BMConfig().get("bmapi", "bm1", "host") + ':' + 
			str(BMConfig().get("bmapi", "bm1", "port")) + '/')
		
		closed = 0
		while not closed:
			try:
				rq = lib.netstring.readns(self.request)
				#print rq
				table, key = rq.split(" ", 1)
			except:
				lib.netstring.writens(self.request, "TEMP Network error")
				closed = 1
				break


			key = key.lower()
			enckey = base64.b64encode(key)

			print "Searching for " + key + " in " + table

			#out = api.listAddressBookEntries(enckey)
			#pprint.pprint(out)
			ret = 0
			try:
				bmaddrs = json.loads(api.listAddressBookEntries(enckey))['addresses']
				for address in bmaddrs:
					if base64.b64decode(address['label']) == key:
						ret = address['address']
			except:
				ret = 1
		
			try:
				if ret == 0:
					lib.netstring.writens(self.request, "NOTFOUND")
				elif ret == 1:
					lib.netstring.writens(self.request, "TEMP Network error")
				else:
					lib.netstring.writens(self.request, "OK bmgateway")
			except:
				closed = 1
				break
