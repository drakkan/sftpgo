#!/usr/bin/env python
import argparse
from datetime import datetime
import json
import platform
import sys
import time

import requests

try:
	import urllib.parse as urlparse
except ImportError:
	import urlparse

try:
	import pygments
	from pygments.lexers import JsonLexer
	from pygments.formatters import TerminalFormatter
except ImportError:
	pygments = None

try:
	import pwd
	import spwd
except ImportError:
	pwd = None


class SFTPGoApiRequests:

	def __init__(self, debug, baseUrl, authType, authUser, authPassword, secure, no_color):
		self.userPath = urlparse.urljoin(baseUrl, '/api/v1/user')
		self.quotaScanPath = urlparse.urljoin(baseUrl, '/api/v1/quota_scan')
		self.activeConnectionsPath = urlparse.urljoin(baseUrl, '/api/v1/connection')
		self.versionPath = urlparse.urljoin(baseUrl, '/api/v1/version')
		self.providerStatusPath = urlparse.urljoin(baseUrl, '/api/v1/providerstatus')
		self.dumpDataPath = urlparse.urljoin(baseUrl, '/api/v1/dumpdata')
		self.loadDataPath = urlparse.urljoin(baseUrl, '/api/v1/loaddata')
		self.debug = debug
		if authType == 'basic':
			self.auth = requests.auth.HTTPBasicAuth(authUser, authPassword)
		elif authType == 'digest':
			self.auth = requests.auth.HTTPDigestAuth(authUser, authPassword)
		else:
			self.auth = None
		self.verify = secure
		self.no_color = no_color

	def formatAsJSON(self, text):
		if not text:
			return ""
		json_string = json.dumps(json.loads(text), sort_keys=True, indent=2)
		if not self.no_color and pygments:
			return pygments.highlight(json_string, JsonLexer(), TerminalFormatter())
		return json_string

	def printResponse(self, r):
		if "content-type" in r.headers and "application/json" in r.headers["content-type"]:
			if self.debug:
				if pygments is None:
					print('')
					print('Response color highlight is not available: you need pygments 1.5 or above.')
				print('')
				print("Executed request: {} {} - request body: {}".format(
					r.request.method, r.url, self.formatAsJSON(r.request.body)))
				print('')
				print("Got response, status code: {} body:".format(r.status_code))
			print(self.formatAsJSON(r.text))
		else:
			print(r.text)

	def buildUserObject(self, user_id=0, username="", password="", public_keys=[], home_dir="", uid=0, gid=0,
					max_sessions=0, quota_size=0, quota_files=0, permissions={}, upload_bandwidth=0, download_bandwidth=0,
					status=1, expiration_date=0, allowed_ip=[], denied_ip=[], fs_provider='local', s3_bucket='',
					s3_region='', s3_access_key='', s3_access_secret='', s3_endpoint='', s3_storage_class=''):
		user = {"id":user_id, "username":username, "uid":uid, "gid":gid,
			"max_sessions":max_sessions, "quota_size":quota_size, "quota_files":quota_files,
			"upload_bandwidth":upload_bandwidth, "download_bandwidth":download_bandwidth,
			"status":status, "expiration_date":expiration_date}
		if password is not None:
			user.update({"password":password})
		if public_keys:
			if len(public_keys) == 1 and not public_keys[0]:
				user.update({"public_keys":[]})
			else:
				user.update({"public_keys":public_keys})
		if home_dir:
			user.update({"home_dir":home_dir})
		if permissions:
			user.update({"permissions":permissions})
		if allowed_ip or denied_ip:
			user.update({"filters":self.buildFilters(allowed_ip, denied_ip)})
		user.update({"filesystem":self.buildFsConfig(fs_provider, s3_bucket, s3_region, s3_access_key,
														s3_access_secret, s3_endpoint, s3_storage_class)})
		return user

	def buildPermissions(self, root_perms, subdirs_perms):
		permissions = {}
		if root_perms:
			permissions.update({"/":root_perms})
		for p in subdirs_perms:
			if ":" in p:
				directory = None
				values = []
				for value in p.split(":"):
					if directory is None:
						directory = value
					else:
						values = [v.strip() for v in value.split(",") if v.strip()]
				if directory and values:
					permissions.update({directory:values})
		return permissions

	def buildFilters(self, allowed_ip, denied_ip):
		filters = {}
		if allowed_ip:
			if len(allowed_ip) == 1 and not allowed_ip[0]:
				filters.update({'allowed_ip':[]})
			else:
				filters.update({'allowed_ip':allowed_ip})
		if denied_ip:
			if len(denied_ip) == 1 and not denied_ip[0]:
				filters.update({'denied_ip':[]})
			else:
				filters.update({'denied_ip':denied_ip})
		return filters

	def buildFsConfig(self, fs_provider, s3_bucket, s3_region, s3_access_key, s3_access_secret, s3_endpoint,
					s3_storage_class):
		fs_config = {'provider':0}
		if fs_provider == 'S3':
			s3config = {'bucket':s3_bucket, 'region':s3_region, 'access_key':s3_access_key, 'access_secret':
					s3_access_secret, 'endpoint':s3_endpoint, 'storage_class':s3_storage_class}
			fs_config.update({'provider':1, 's3config':s3config})
		return fs_config

	def getUsers(self, limit=100, offset=0, order="ASC", username=""):
		r = requests.get(self.userPath, params={"limit":limit, "offset":offset, "order":order,
											"username":username}, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def getUserByID(self, user_id):
		r = requests.get(urlparse.urljoin(self.userPath, "user/" + str(user_id)), auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def addUser(self, username="", password="", public_keys="", home_dir="", uid=0, gid=0, max_sessions=0, quota_size=0,
			quota_files=0, perms=[], upload_bandwidth=0, download_bandwidth=0, status=1, expiration_date=0,
			subdirs_permissions=[], allowed_ip=[], denied_ip=[], fs_provider='local', s3_bucket='', s3_region='',
			s3_access_key='', s3_access_secret='', s3_endpoint='', s3_storage_class=''):
		u = self.buildUserObject(0, username, password, public_keys, home_dir, uid, gid, max_sessions,
			quota_size, quota_files, self.buildPermissions(perms, subdirs_permissions), upload_bandwidth, download_bandwidth,
			status, expiration_date, allowed_ip, denied_ip, fs_provider, s3_bucket, s3_region,
			s3_access_key, s3_access_secret, s3_endpoint, s3_storage_class)
		r = requests.post(self.userPath, json=u, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def updateUser(self, user_id, username="", password="", public_keys="", home_dir="", uid=0, gid=0, max_sessions=0,
				quota_size=0, quota_files=0, perms=[], upload_bandwidth=0, download_bandwidth=0, status=1,
				expiration_date=0, subdirs_permissions=[], allowed_ip=[], denied_ip=[], fs_provider='local',
				s3_bucket='', s3_region='', s3_access_key='', s3_access_secret='', s3_endpoint='', s3_storage_class=''):
		u = self.buildUserObject(user_id, username, password, public_keys, home_dir, uid, gid, max_sessions,
			quota_size, quota_files, self.buildPermissions(perms, subdirs_permissions), upload_bandwidth, download_bandwidth,
			status, expiration_date, allowed_ip, denied_ip, fs_provider, s3_bucket, s3_region, s3_access_key,
			s3_access_secret, s3_endpoint, s3_storage_class)
		r = requests.put(urlparse.urljoin(self.userPath, "user/" + str(user_id)), json=u, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def deleteUser(self, user_id):
		r = requests.delete(urlparse.urljoin(self.userPath, "user/" + str(user_id)), auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def getConnections(self):
		r = requests.get(self.activeConnectionsPath, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def closeConnection(self, connectionID):
		r = requests.delete(urlparse.urljoin(self.activeConnectionsPath, "connection/" + str(connectionID)), auth=self.auth)
		self.printResponse(r)

	def getQuotaScans(self):
		r = requests.get(self.quotaScanPath, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def startQuotaScan(self, username):
		u = self.buildUserObject(0, username)
		r = requests.post(self.quotaScanPath, json=u, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def getVersion(self):
		r = requests.get(self.versionPath, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def getProviderStatus(self):
		r = requests.get(self.providerStatusPath, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def dumpData(self, output_file):
		r = requests.get(self.dumpDataPath, params={"output_file":output_file}, auth=self.auth,
						verify=self.verify)
		self.printResponse(r)

	def loadData(self, input_file, scan_quota):
		r = requests.get(self.loadDataPath, params={"input_file":input_file, "scan_quota":scan_quota},
						auth=self.auth, verify=self.verify)
		self.printResponse(r)


class ConvertUsers:

	def __init__(self, input_file, users_format, output_file, min_uid, max_uid, usernames, force_uid, force_gid):
		self.input_file = input_file
		self.users_format = users_format
		self.output_file = output_file
		self.min_uid = min_uid
		self.max_uid = max_uid
		self.usernames = usernames
		self.force_uid = force_uid
		self.force_gid = force_gid
		self.SFTPGoUsers = []

	def setSFTPGoRestApi(self, api):
		self.SFTPGoRestAPI = api

	def addUser(self, user):
		user["id"] = len(self.SFTPGoUsers) + 1
		print('')
		print('New user imported: {}'.format(user))
		print('')
		self.SFTPGoUsers.append(user)

	def saveUsers(self):
		if self.SFTPGoUsers:
			data = {"users":self.SFTPGoUsers}
			jsonData = json.dumps(data)
			with open(self.output_file, 'w') as f:
				f.write(jsonData)
			print()
			print('Number of users saved to "{}": {}. You can import them using loaddata'.format(self.output_file,
																								len(self.SFTPGoUsers)))
			print()
			sys.exit(0)
		else:
			print('No user imported')
			sys.exit(1)

	def convert(self):
		if self.users_format == "unix-passwd":
			self.convertFromUnixPasswd()
		elif self.users_format == "pure-ftpd":
			self.convertFromPureFTPD()
		else:
			self.convertFromProFTPD()
		self.saveUsers()

	def isUserValid(self, username, uid):
		if self.usernames and not username in self.usernames:
			return False
		if self.min_uid >= 0 and uid < self.min_uid:
			return False
		if self.max_uid >= 0 and uid > self.max_uid:
			return False
		return True

	def convertFromUnixPasswd(self):
		days_from_epoch_time = time.time() / 86400
		for user in pwd.getpwall():
			username = user.pw_name
			password = user.pw_passwd
			uid = user.pw_uid
			gid = user.pw_gid
			home_dir = user.pw_dir
			status = 1
			expiration_date = 0
			if not self.isUserValid(username, uid):
				continue
			if self.force_uid >= 0:
				uid = self.force_uid
			if self.force_gid >= 0:
				gid = self.force_gid
			# FIXME: if the passwords aren't in /etc/shadow they are probably DES encrypted and we don't support them
			if password == 'x' or password == '*':
				user_info = spwd.getspnam(username)
				password = user_info.sp_pwdp
				if not password or password == '!!':
					print('cannot import user "{}" without a password'.format(username))
					continue
				if user_info.sp_inact > 0:
					last_pwd_change_diff = days_from_epoch_time - user_info.sp_lstchg
					if last_pwd_change_diff > user_info.sp_inact:
						status = 0
				if user_info.sp_expire > 0:
					expiration_date = user_info.sp_expire * 86400
			permissions = self.SFTPGoRestAPI.buildPermissions(['*'], [])
			self.addUser(self.SFTPGoRestAPI.buildUserObject(0, username, password, [], home_dir, uid, gid, 0, 0, 0,
														permissions, 0, 0, status, expiration_date))

	def convertFromProFTPD(self):
		with open(self.input_file, 'r') as f:
			for line in f:
				fields = line.split(':')
				if len(fields) > 6:
					username = fields[0]
					password = fields[1]
					uid = int(fields[2])
					gid = int(fields[3])
					home_dir = fields[5]
					if not self.isUserValid(username, uid, gid):
						continue
					if self.force_uid >= 0:
						uid = self.force_uid
					if self.force_gid >= 0:
						gid = self.force_gid
					permissions = self.SFTPGoRestAPI.buildPermissions(['*'], [])
					self.addUser(self.SFTPGoRestAPI.buildUserObject(0, username, password, [], home_dir, uid, gid, 0, 0,
																0, permissions, 0, 0, 1, 0))

	def convertPureFTPDIP(self, fields):
		result = []
		if not fields:
			return result
		for v in fields.split(","):
			ip_mask = v.strip()
			if not ip_mask:
				continue
			if ip_mask.count(".") < 3 and ip_mask.count(":") < 3:
				print("cannot import pure-ftpd IP: {}".format(ip_mask))
				continue
			if "/" not in ip_mask:
				ip_mask += "/32"
			result.append(ip_mask)
		return result

	def convertFromPureFTPD(self):
		with open(self.input_file, 'r') as f:
			for line in f:
				fields = line.split(':')
				if len(fields) > 16:
					username = fields[0]
					password = fields[1]
					uid = int(fields[2])
					gid = int(fields[3])
					home_dir = fields[5]
					upload_bandwidth = 0
					if fields[6]:
						upload_bandwidth = int(int(fields[6]) / 1024)
					download_bandwidth = 0
					if fields[7]:
						download_bandwidth = int(int(fields[7]) / 1024)
					max_sessions = 0
					if fields[10]:
						max_sessions = int(fields[10])
					quota_files = 0
					if fields[11]:
						quota_files = int(fields[11])
					quota_size = 0
					if fields[12]:
						quota_size = int(fields[12])
					allowed_ip = self.convertPureFTPDIP(fields[15])
					denied_ip = self.convertPureFTPDIP(fields[16])
					if not self.isUserValid(username, uid, gid):
						continue
					if self.force_uid >= 0:
						uid = self.force_uid
					if self.force_gid >= 0:
						gid = self.force_gid
					permissions = self.SFTPGoRestAPI.buildPermissions(['*'], [])
					self.addUser(self.SFTPGoRestAPI.buildUserObject(0, username, password, [], home_dir, uid, gid,
																max_sessions, quota_size, quota_files, permissions,
																upload_bandwidth, download_bandwidth, 1, 0, allowed_ip,
																denied_ip))


def validDate(s):
	if not s:
		return datetime.fromtimestamp(0)
	try:
		return datetime.strptime(s, "%Y-%m-%d")
	except ValueError:
		msg = "Not a valid date: '{0}'.".format(s)
		raise argparse.ArgumentTypeError(msg)


def getDatetimeAsMillisSinceEpoch(dt):
	epoch = datetime.fromtimestamp(0)
	return int((dt - epoch).total_seconds() * 1000)


def addCommonUserArguments(parser):
	parser.add_argument('username', type=str)
	parser.add_argument('-P', '--password', type=str, default=None, help='Default: %(default)s')
	parser.add_argument('-K', '--public-keys', type=str, nargs='+', default=[], help='Default: %(default)s')
	parser.add_argument('-H', '--home-dir', type=str, default='', help='Default: %(default)s')
	parser.add_argument('--uid', type=int, default=0, help='Default: %(default)s')
	parser.add_argument('--gid', type=int, default=0, help='Default: %(default)s')
	parser.add_argument('-C', '--max-sessions', type=int, default=0,
					help='Maximum concurrent sessions. 0 means unlimited. Default: %(default)s')
	parser.add_argument('-S', '--quota-size', type=int, default=0,
					help='Maximum size allowed as bytes. 0 means unlimited. Default: %(default)s')
	parser.add_argument('-F', '--quota-files', type=int, default=0, help="default: %(default)s")
	parser.add_argument('-G', '--permissions', type=str, nargs='+', default=[],
					choices=['*', 'list', 'download', 'upload', 'overwrite', 'delete', 'rename', 'create_dirs',
							'create_symlinks', 'chmod', 'chown', 'chtimes'], help='Permissions for the root directory '
							+'(/). Default: %(default)s')
	parser.add_argument('--subdirs-permissions', type=str, nargs='*', default=[], help='Permissions for subdirs. '
					+'For example: "/somedir:list,download" "/otherdir/subdir:*" Default: %(default)s')
	parser.add_argument('-U', '--upload-bandwidth', type=int, default=0,
					help='Maximum upload bandwidth as KB/s, 0 means unlimited. Default: %(default)s')
	parser.add_argument('-D', '--download-bandwidth', type=int, default=0,
					help='Maximum download bandwidth as KB/s, 0 means unlimited. Default: %(default)s')
	parser.add_argument('--status', type=int, choices=[0, 1], default=1,
							help='User\'s status. 1 enabled, 0 disabled. Default: %(default)s')
	parser.add_argument('-E', '--expiration-date', type=validDate, default="",
					help='Expiration date as YYYY-MM-DD, empty string means no expiration. Default: %(default)s')
	parser.add_argument('-Y', '--allowed-ip', type=str, nargs='+', default=[],
					help='Allowed IP/Mask in CIDR notation. For example "192.168.2.0/24" or "2001:db8::/32". Default: %(default)s')
	parser.add_argument('-N', '--denied-ip', type=str, nargs='+', default=[],
					help='Denied IP/Mask in CIDR notation. For example "192.168.2.0/24" or "2001:db8::/32". Default: %(default)s')
	parser.add_argument('--fs', type=str, default='local', choices=['local', 'S3'],
					help='Filesystem provider. Default: %(default)s')
	parser.add_argument('--s3-bucket', type=str, default='', help='Default: %(default)s')
	parser.add_argument('--s3-region', type=str, default='', help='Default: %(default)s')
	parser.add_argument('--s3-access-key', type=str, default='', help='Default: %(default)s')
	parser.add_argument('--s3-access-secret', type=str, default='', help='Default: %(default)s')
	parser.add_argument('--s3-endpoint', type=str, default='', help='Default: %(default)s')
	parser.add_argument('--s3-storage-class', type=str, default='', help='Default: %(default)s')


if __name__ == '__main__':
	parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('-b', '--base-url', type=str, default='http://127.0.0.1:8080',
					help='Base URL for SFTPGo REST API. Default: %(default)s')
	parser.add_argument('-a', '--auth-type', type=str, default=None, choices=['basic', 'digest'],
					help='HTTP authentication type. Default: %(default)s')
	parser.add_argument("-u", "--auth-user", type=str, default="",
					help='User for HTTP authentication. Default: %(default)s')
	parser.add_argument('-p', '--auth-password', type=str, default='',
					help='Password for HTTP authentication. Default: %(default)s')
	parser.add_argument('-d', '--debug', dest='debug', action='store_true')
	parser.set_defaults(debug=False)
	parser.add_argument('-i', '--insecure', dest='secure', action='store_false',
					help='Set to false to ignore verifying the SSL certificate')
	parser.set_defaults(secure=True)
	has_colors_default = pygments is not None and platform.system() != "Windows"
	group = parser.add_mutually_exclusive_group(required=False)
	group.add_argument('-t', '--no-color', dest='no_color', action='store_true', default=(not has_colors_default),
					help='Disable color highlight for JSON responses. You need python pygments module 1.5 or above to have highlighted output')
	group.add_argument('-c', '--color', dest='no_color', action='store_false', default=has_colors_default,
					help='Enable color highlight for JSON responses. You need python pygments module 1.5 or above to have highlighted output')
	parser.add_argument_group(group)

	subparsers = parser.add_subparsers(dest='command', help='sub-command --help')
	subparsers.required = True

	parserAddUser = subparsers.add_parser('add-user', help='Add a new SFTP user')
	addCommonUserArguments(parserAddUser)

	parserUpdateUser = subparsers.add_parser('update-user', help='Update an existing user')
	parserUpdateUser.add_argument('id', type=int, help='User\'s ID to update')
	addCommonUserArguments(parserUpdateUser)

	parserDeleteUser = subparsers.add_parser('delete-user', help='Delete an existing user')
	parserDeleteUser.add_argument('id', type=int, help='User\'s ID to delete')

	parserGetUsers = subparsers.add_parser('get-users', help='Returns an array with one or more SFTP users')
	parserGetUsers.add_argument('-L', '--limit', type=int, default=100, choices=range(1, 501),
							help='Maximum allowed value is 500. Default: %(default)s', metavar='[1...500]')
	parserGetUsers.add_argument('-O', '--offset', type=int, default=0, help='Default: %(default)s')
	parserGetUsers.add_argument('-U', '--username', type=str, default='', help='Default: %(default)s')
	parserGetUsers.add_argument('-S', '--order', type=str, choices=['ASC', 'DESC'], default='ASC',
							help='default: %(default)s')

	parserGetUserByID = subparsers.add_parser('get-user-by-id', help='Find user by ID')
	parserGetUserByID.add_argument('id', type=int)

	parserGetConnections = subparsers.add_parser('get-connections',
													help='Get the active users and info about their uploads/downloads')

	parserCloseConnection = subparsers.add_parser('close-connection', help='Terminate an active SFTP/SCP connection')
	parserCloseConnection.add_argument('connectionID', type=str)

	parserGetQuotaScans = subparsers.add_parser('get-quota-scans', help='Get the active quota scans')

	parserStartQuotaScans = subparsers.add_parser('start-quota-scan', help='Start a new quota scan')
	addCommonUserArguments(parserStartQuotaScans)

	parserGetVersion = subparsers.add_parser('get-version', help='Get version details')

	parserGetProviderStatus = subparsers.add_parser('get-provider-status', help='Get data provider status')

	parserDumpData = subparsers.add_parser('dumpdata', help='Backup SFTPGo data serializing them as JSON')
	parserDumpData.add_argument('output_file', type=str)

	parserLoadData = subparsers.add_parser('loaddata', help='Restore SFTPGo data from a JSON backup')
	parserLoadData.add_argument('input_file', type=str)
	parserLoadData.add_argument('-Q', '--scan-quota', type=int, choices=[0, 1, 2], default=0,
							help='0 means no quota scan after a user is added/updated. 1 means always scan quota. 2 ' +
							'means scan quota if the user has quota restrictions. Default: %(default)s')

	parserConvertUsers = subparsers.add_parser('convert-users', help='Convert users to a JSON format suitable to use with loadddata')
	supportedUsersFormats = []
	help_text = ''
	if pwd is not None:
		supportedUsersFormats.append("unix-passwd")
		help_text = 'To import from unix-passwd format you need the permission to read /etc/shadow that is typically granted to the root user only'
	supportedUsersFormats.append("pure-ftpd")
	supportedUsersFormats.append("proftpd")
	parserConvertUsers.add_argument('input_file', type=str)
	parserConvertUsers.add_argument('users_format', type=str, choices=supportedUsersFormats, help=help_text)
	parserConvertUsers.add_argument('output_file', type=str)
	parserConvertUsers.add_argument('--min-uid', type=int, default=-1, help='if >= 0 only import users with UID greater ' +
								'or equal to this value. Default: %(default)s')
	parserConvertUsers.add_argument('--max-uid', type=int, default=-1, help='if >= 0 only import users with UID lesser ' +
								'or equal to this value. Default: %(default)s')
	parserConvertUsers.add_argument('--usernames', type=str, nargs='+', default=[], help='Only import users with these ' +
								'usernames. Default: %(default)s')
	parserConvertUsers.add_argument('--force-uid', type=int, default=-1, help='if >= 0 the imported users will have this UID in SFTPGo. Default: %(default)s')
	parserConvertUsers.add_argument('--force-gid', type=int, default=-1, help='if >= 0 the imported users will have this GID in SFTPGp. Default: %(default)s')

	args = parser.parse_args()

	api = SFTPGoApiRequests(args.debug, args.base_url, args.auth_type, args.auth_user, args.auth_password, args.secure,
						 args.no_color)

	if args.command == 'add-user':
		api.addUser(args.username, args.password, args.public_keys, args.home_dir, args.uid, args.gid, args.max_sessions,
				args.quota_size, args.quota_files, args.permissions, args.upload_bandwidth, args.download_bandwidth,
				args.status, getDatetimeAsMillisSinceEpoch(args.expiration_date), args.subdirs_permissions, args.allowed_ip,
				args.denied_ip, args.fs, args.s3_bucket, args.s3_region, args.s3_access_key, args.s3_access_secret,
				args.s3_endpoint, args.s3_storage_class)
	elif args.command == 'update-user':
		api.updateUser(args.id, args.username, args.password, args.public_keys, args.home_dir, args.uid, args.gid,
					args.max_sessions, args.quota_size, args.quota_files, args.permissions, args.upload_bandwidth,
					args.download_bandwidth, args.status, getDatetimeAsMillisSinceEpoch(args.expiration_date),
					args.subdirs_permissions, args.allowed_ip, args.denied_ip, args.fs, args.s3_bucket, args.s3_region,
					args.s3_access_key, args.s3_access_secret, args.s3_endpoint, args.s3_storage_class)
	elif args.command == 'delete-user':
		api.deleteUser(args.id)
	elif args.command == 'get-users':
		api.getUsers(args.limit, args.offset, args.order, args.username)
	elif args.command == 'get-user-by-id':
		api.getUserByID(args.id)
	elif args.command == 'get-connections':
		api.getConnections()
	elif args.command == 'close-connection':
		api.closeConnection(args.connectionID)
	elif args.command == 'get-quota-scans':
		api.getQuotaScans()
	elif args.command == 'start-quota-scan':
		api.startQuotaScan(args.username)
	elif args.command == 'get-version':
		api.getVersion()
	elif args.command == 'get-provider-status':
		api.getProviderStatus()
	elif args.command == 'dumpdata':
		api.dumpData(args.output_file)
	elif args.command == 'loaddata':
		api.loadData(args.input_file, args.scan_quota)
	elif args.command == 'convert-users':
		convertUsers = ConvertUsers(args.input_file, args.users_format, args.output_file, args.min_uid, args.max_uid,
								args.usernames, args.force_uid, args.force_gid)
		convertUsers.setSFTPGoRestApi(api)
		convertUsers.convert()
