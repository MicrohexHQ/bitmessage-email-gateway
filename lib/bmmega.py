#!/usr/bin/python2.7

from lib.config import BMConfig
from lib.mysql import BMMySQL
import logging
from mega import Mega
import sys
import time
import pprint

def mega_login():
	mega = Mega({'verbose': False})
	try:
		m = mega.login(BMConfig().get("bmgateway", "mega", "username"), BMConfig().get("bmgateway", "mega", "password"))
	except:
		logging.error ("Mega login error")
		return None
	return m

def mega_upload(bm, fname, data):
	m = mega_login()
	if m == None:
		return None, None
	foldername = BMConfig().get("bmgateway", "mega", "folder")
	folder = m.find(foldername)
	loops = 30
	while folder == None and loops > 0:
		try:
			m.create_folder(foldername)
			folder = m.find(foldername)
		except:
			pass
		if folder == None:
			time.sleep (1)
		loops -= 1
	if folder == None:
		return None, None

	
	uploadedfile = None
	loops = 30
	while uploadedfile == None and loops > 0:
		try:
			uploadedfile = m.upload(data, folder[0], dest_filename=fname, save_key=False)
		except:
			pass
		if uploadedfile == None:
			time.sleep (1)
		loops -= 1
		
	file_id = uploadedfile['f'][0]['h']
	link = m.get_upload_link(uploadedfile)
	cur = BMMySQL().conn().cursor()
	cur.execute ("INSERT IGNORE INTO mega (fileid, bm) VALUES (%s, %s)", (
		file_id, bm))
	cur.close()
	return file_id, link

def search_fileids(ackdata):
	fileids = []
	# cur.execute("SELECT fileid FROM mega WHERE ackdata = %s", (ackdata.decode("hex")))
	# cur.close()
	# loop results
	
	return fileids

def mega_delete(file_id):
	m = mega_login()
	if m == None:
		return False
	retval = m.delete(file_id)
	#if retval == 0:
		# cur.execute("DELETE FROM mega WHERE fileid = %s", (file_id))
		# cur.close()

	return retval

# download from an url
#m.download_from_url('https://mega.co.nz/#!wYo3AYZC!Zwi1f3ANtYwKNOc07fwuN1enOoRj4CreFouuGqi4D6Y')

