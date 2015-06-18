#!/usr/bin/python2.7

from lib.config import BMConfig
from lib.mysql import BMMySQL
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
	loops = 10
	while folder == None and loops > 0:
		m.create_folder(foldername)
		folder = m.find(foldername)
		if folder == None:
			time.sleep (1)
		loops -= 1
	if folder == None:
		return None, None

	uploadedfile = m.upload(data, folder[0], dest_filename=fname, save_key=False)
	file_id = uploadedfile['f'][0]['h']
	link = m.get_upload_link(uploadedfile)
	BMMySQL().db.ping(True)
	cur = BMMySQL().db.cursor()
	cur.execute ("INSERT IGNORE INTO mega (fileid, bm) VALUES (%s, %s)", (
		file_id, bm))
	cur.close()
	return file_id, link

def mega_delete(file_id):
	m = mega_login()
	if m == None:
		return False
	retval = m.delete(file_id)
	return retval

# download from an url
#m.download_from_url('https://mega.co.nz/#!wYo3AYZC!Zwi1f3ANtYwKNOc07fwuN1enOoRj4CreFouuGqi4D6Y')

