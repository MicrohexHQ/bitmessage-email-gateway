#!/usr/bin/python

import chardet

class SafeDecodeError(Exception):
	def __init__(self, message):
		self.message = message

def safeDecode(text, charset = None):
	if isinstance(text, unicode):
		return text
	if charset is not None:
		try:
			return text.decode(charset)
		except:
			pass
	try:
		detected_charset = chardet.detect(text)
		if detected_charset['encoding']:
			return text.decode(detected_charset['encoding'], errors='replace')
	except:
		raise SafeDecodeError("SafeDecode failed to detect charset")
