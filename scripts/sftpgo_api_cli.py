#!/usr/bin/env python
import argparse
import json

import requests

try:
	import urllib.parse as urlparse
except ImportError:
	import urlparse


class SFTPGoApiRequests:

	def __init__(self, debug, baseUrl, authType, authUser, authPassword, verify):
		self.userPath = urlparse.urljoin(baseUrl, "/api/v1/user")
		self.quotaScanPath = urlparse.urljoin(baseUrl, "/api/v1/quota_scan")
		self.activeConnectionsPath = urlparse.urljoin(baseUrl, "/api/v1/sftp_connection")
		self.debug = debug
		if authType == "basic":
			self.auth = requests.auth.HTTPBasicAuth(authUser, authPassword)
		elif authType == "digest":
			self.auth = requests.auth.HTTPDigestAuth(authUser, authPassword)
		else:
			self.auth = None
		self.verify = verify

	def formatAsJSON(self, text):
		if not text:
			return ""
		return json.dumps(json.loads(text), indent=2)

	def printResponse(self, r):
		if "content-type" in r.headers and "application/json" in r.headers["content-type"]:
			if self.debug:
				print("executed request: {} {} - status code: {} request body: {}".format(
					r.request.method, r.url, r.status_code, self.formatAsJSON(r.request.body)))
				print("got response, status code: {} body:".format(r.status_code))
			print(self.formatAsJSON(r.text))
		else:
			print(r.text)

	def buildUserObject(self, user_id=0, username="", password="", public_keys="", home_dir="", uid=0,
					gid=0, max_sessions=0, quota_size=0, quota_files=0, permissions=[], upload_bandwidth=0,
					download_bandwidth=0):
		user = {"id":user_id, "username":username, "home_dir":home_dir, "uid":uid, "gid":gid,
			"max_sessions":max_sessions, "quota_size":quota_size, "quota_files":quota_files,
			"permissions":permissions, "upload_bandwidth":upload_bandwidth,
			"download_bandwidth":download_bandwidth}
		if password:
			user.update({"password":password})
		if public_keys:
			user.update({"public_keys":public_keys})
		return user

	def getUsers(self, limit=100, offset=0, order="ASC", username=""):
		r = requests.get(self.userPath, params={"limit":limit, "offset":offset, "order":order,
											"username":username}, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def getUserByID(self, user_id):
		r = requests.get(urlparse.urljoin(self.userPath, "user/" + str(user_id)), auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def addUser(self, username="", password="", public_keys="", home_dir="", uid=0, gid=0, max_sessions=0,
		quota_size=0, quota_files=0, permissions=[], upload_bandwidth=0, download_bandwidth=0):
		u = self.buildUserObject(0, username, password, public_keys, home_dir, uid, gid, max_sessions,
			quota_size, quota_files, permissions, upload_bandwidth, download_bandwidth)
		r = requests.post(self.userPath, json=u, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def updateUser(self, user_id, username="", password="", public_keys="", home_dir="", uid=0, gid=0,
				max_sessions=0, quota_size=0, quota_files=0, permissions=[], upload_bandwidth=0,
				download_bandwidth=0):
		u = self.buildUserObject(user_id, username, password, public_keys, home_dir, uid, gid, max_sessions,
			quota_size, quota_files, permissions, upload_bandwidth, download_bandwidth)
		r = requests.put(urlparse.urljoin(self.userPath, "user/" + str(user_id)), json=u, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def deleteUser(self, user_id):
		r = requests.delete(urlparse.urljoin(self.userPath, "user/" + str(user_id)), auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def getSFTPConnections(self):
		r = requests.get(self.activeConnectionsPath, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def closeSFTPConnection(self, connectionID):
		r = requests.delete(urlparse.urljoin(self.userPath, "sftp_connection/" + str(connectionID)), auth=self.auth)
		self.printResponse(r)

	def getQuotaScans(self):
		r = requests.get(self.quotaScanPath, auth=self.auth, verify=self.verify)
		self.printResponse(r)

	def startQuotaScan(self, username):
		u = self.buildUserObject(0, username)
		r = requests.post(self.quotaScanPath, json=u, auth=self.auth, verify=self.verify)
		self.printResponse(r)


def addCommonUserArguments(parser):
	parser.add_argument('username', type=str)
	parser.add_argument('--password', type=str, default="", help="default: %(default)s")
	parser.add_argument('--public_keys', type=str, nargs='+', default=[], help="default: %(default)s")
	parser.add_argument('--home_dir', type=str, default="", help="default: %(default)s")
	parser.add_argument('--uid', type=int, default=0, help="default: %(default)s")
	parser.add_argument('--gid', type=int, default=0, help="default: %(default)s")
	parser.add_argument('--max_sessions', type=int, default=0, help="default: %(default)s")
	parser.add_argument('--quota_size', type=int, default=0, help="default: %(default)s")
	parser.add_argument('--quota_files', type=int, default=0, help="default: %(default)s")
	parser.add_argument('--permissions', type=str, nargs='+', default=[],
					choices=['*', 'list', 'download', 'upload', 'delete', 'rename', 'create_dirs',
							'create_symlinks'], help="default: %(default)s")
	parser.add_argument('--upload_bandwidth', type=int, default=0, help="default: %(default)s")
	parser.add_argument('--download_bandwidth', type=int, default=0, help="default: %(default)s")


if __name__ == '__main__':
	parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument("--base_url", type=str, default="http://127.0.0.1:8080",
					help="Base URL for SFTPGo REST API. Default: %(default)s")
	parser.add_argument("--auth_type", type=str, default=None, choices=["basic", "digest"],
					help="Authentication type to use. Default: %(default)s")
	parser.add_argument("--auth_user", type=str, default="",
					help="User to use for authentication. Default: %(default)s")
	parser.add_argument("--auth_password", type=str, default="",
					help="Password to use for authentication. Default: %(default)s")
	parser.add_argument("--debug", dest='debug', action='store_true')
	parser.set_defaults(debug=False)
	parser.add_argument("--verify", dest='verify', action='store_true',
					help="Set to false to ignore verifying the SSL certificate")
	parser.set_defaults(verify=True)

	subparsers = parser.add_subparsers(dest="command", help='sub-command --help')
	subparsers.required = True

	parserAddUser = subparsers.add_parser("add_user", help="Add a new SFTP user")
	addCommonUserArguments(parserAddUser)

	parserUpdateUser = subparsers.add_parser("update_user", help="Update an existing user")
	parserUpdateUser.add_argument('id', type=int)
	addCommonUserArguments(parserUpdateUser)

	parserDeleteUser = subparsers.add_parser("delete_user", help="Delete an existing user")
	parserDeleteUser.add_argument('id', type=int)

	parserGetUsers = subparsers.add_parser("get_users", help="Returns an array with one or more SFTP users")
	parserGetUsers.add_argument('--limit', type=int, default=100, help="default: %(default)s")
	parserGetUsers.add_argument('--offset', type=int, default=0, help="default: %(default)s")
	parserGetUsers.add_argument('--username', type=str, default="", help="default: %(default)s")
	parserGetUsers.add_argument('--order', type=str, choices=['ASC', 'DESC'], default='ASC',
							help="default: %(default)s")

	parserGetUserByID = subparsers.add_parser("get_user_by_id", help="Find user by ID")
	parserGetUserByID.add_argument('id', type=int)

	parserGetSFTPConnections = subparsers.add_parser("get_sftp_connections", help="Get the active sftp users and info about their uploads/downloads")

	parserCloseSFTPConnection = subparsers.add_parser("close_sftp_connection", help="Terminate an active SFTP connection")
	parserCloseSFTPConnection.add_argument("connectionID", type=str)

	parserGetQuotaScans = subparsers.add_parser("get_quota_scans", help="Get the active quota scans")

	parserStartQuotaScans = subparsers.add_parser("start_quota_scan", help="Start a new quota scan")
	addCommonUserArguments(parserStartQuotaScans)

	args = parser.parse_args()

	api = SFTPGoApiRequests(args.debug, args.base_url, args.auth_type, args.auth_user, args.auth_password, args.verify)

	if args.command == "add_user":
		api.addUser(args.username, args.password, args.public_keys, args.home_dir,
					args.uid, args.gid, args.max_sessions, args.quota_size, args.quota_files,
					args.permissions, args.upload_bandwidth, args.download_bandwidth)
	elif args.command == "update_user":
		api.updateUser(args.id, args.username, args.password, args.public_keys, args.home_dir,
					args.uid, args.gid, args.max_sessions, args.quota_size, args.quota_files,
					args.permissions, args.upload_bandwidth, args.download_bandwidth)
	elif args.command == "delete_user":
		api.deleteUser(args.id)
	elif args.command == "get_users":
		api.getUsers(args.limit, args.offset, args.order, args.username)
	elif args.command == "get_user_by_id":
		api.getUserByID(args.id)
	elif args.command == "get_sftp_connections":
		api.getSFTPConnections()
	elif args.command == "close_sftp_connection":
		api.closeSFTPConnection(args.connectionID)
	elif args.command == "get_quota_scans":
		api.getQuotaScans()
	elif args.command == "start_quota_scan":
		api.startQuotaScan(args.username)

