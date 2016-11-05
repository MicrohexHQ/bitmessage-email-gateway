from binascii import unhexlify
import MySQLdb
from warnings import filterwarnings

from lib.mysql import BMMySQL

def check_message_processed(msgid):
	cur = BMMySQL().conn().cursor(MySQLdb.cursors.DictCursor)
	filterwarnings('ignore', category = MySQLdb.Warning)
	cur.execute ("UPDATE inboxids SET lastseen = UNIX_TIMESTAMP(NOW()) WHERE msgid = %s", (unhexlify(msgid)))
	if cur.rowcount >= 1:
		cur.close()
		return True
	else:
		cur.close()
		return False

def set_message_processed(msgid):
	cur = BMMySQL().conn().cursor(MySQLdb.cursors.DictCursor)
	filterwarnings('ignore', category = MySQLdb.Warning)
	cur.execute ("INSERT INTO inboxids (msgid, lastseen) VALUES (%s, UNIX_TIMESTAMP(NOW())) ON DUPLICATE KEY UPDATE lastseen = UNIX_TIMESTAMP(NOW())", (unhexlify(msgid)))
	cur.close()
