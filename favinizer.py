#!/usr/bin/python3

import requests
import optparse
import sys
import os
import concurrent.futures
import yaml
import codecs
import hashlib
import urllib.parse
import urllib.request
import mmh3 
import ssl

BLUE='\033[94m'
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CLEAR='\x1b[0m'

print(BLUE + "Favinizer[1.0] by ARPSyndicate" + CLEAR)
print(YELLOW + "favicon fingerprinting" + CLEAR)

if len(sys.argv)<2:
	print(RED + "[!] ./favinizer --help" + CLEAR)
	sys.exit()

else:
	parser = optparse.OptionParser()
	parser.add_option('-l', '--list', action="store", dest="list", help="list of targets to check")
	parser.add_option('-o', '--output', action="store", dest="output", help="output file")
	parser.add_option('-v', '--verbose', action="store_true", dest="verbose", help="prints error messages [default=false]", default=False)
	parser.add_option('-t', '--timeout', action="store", dest="timeout", help="timeout in seconds [default=5]", default=5)
	parser.add_option('-T', '--threads', action="store", dest="threads", help="maximum threads [default=20]", default=20)
	parser.add_option('-d', '--database', action="store", dest="db", help="signatures database [default=./favinizer.yaml]", default="favinizer.yaml")
	parser.add_option('--only-md5', action="store_false", dest="mmh3", help="match only against md5 signatures", default=True)
	parser.add_option('--only-mmh3', action="store_false", dest="md5", help="match only against mmh3 signatures", default=True)

inputs,args  = parser.parse_args()
if not inputs.list:
	parser.error(RED + "[!] list of targets not given" + CLEAR)

list = str(inputs.list)
db = str(inputs.db)
md = inputs.md5
mmh = inputs.mmh3
output = str(inputs.output)
verbose = inputs.verbose
timeout = int(inputs.timeout)
threads = int(inputs.threads)
result = []

try:
	with open(db) as signatures:
		sig = yaml.load(signatures, Loader=yaml.FullLoader)
except:
	print(RED + "[!] invalid signatures database" + CLEAR)
sigmd5 = sig['md5']
sigmmh3 = sig['mmh3']

with open(list) as f:
	targets=f.read().splitlines()

def checkMD5(sign):
		return sigmd5.get(sign, False)

def checkMMH3(sign):
		return sigmmh3.get(sign, False)

def getMD5(url):
	try:
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		res = urllib.request.urlopen(url, timeout=timeout, context=context)
		fav = codecs.encode(res.read(),"base64")
		return hashlib.md5(fav).hexdigest()
	except:
		return None
	
def getMMH3(url):
	try:
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		res = urllib.request.urlopen(url, timeout=timeout, context=context)
		fav = codecs.encode(res.read(),"base64")
		return mmh3.hash(fav)
	except:
		return None

def checkAll(url):
	target = '{uri.scheme}://{uri.netloc}/'.format(uri=urllib.parse.urlparse(url))
	if md:
		sig = getMD5(url)
		if  sig != None:
			fnd = checkMD5(sig)
			if fnd != False:
				print(BLUE + "[+]\t{0}\t{1} [{2}]".format(target, str(sig), fnd) + CLEAR)
				result.append("{1}\t{2}\t{0}".format(target, str(sig), fnd))
			else:
				print(GREEN + "[*]\t{0}\t{1} [{2}]".format(target, str(sig), "SIGNATURE NOT FOUND") + CLEAR)
				result.append("{1}\t[{2}]\t{0}".format(target, str(sig), "SIGNATURE NOT FOUND"))
		else:
			if verbose:
				print(RED + "[REQ ERR]\t"+target + CLEAR)
	if mmh:
		sig = getMMH3(url)
		if  sig != None:
			fnd = checkMMH3(sig)
			if fnd != False:
				print(BLUE + "[+]\t{0}\t{1} [{2}]".format(target, sig, fnd) + CLEAR)
				result.append("{1}\t{2}\t{0}".format(target, str(sig), fnd))
			else:
				print(GREEN + "[*]\t{0}\t{1} [{2}]".format(target, sig, "SIGNATURE NOT FOUND") + CLEAR)
				result.append("{1}\t[{2}]\t{0}".format(target, str(sig), "SIGNATURE NOT FOUND"))
		else:
			if verbose:
				print(RED + "[REQ ERR]\t"+target + CLEAR)
				
def generatePerms(targets):
	perms=[]
	for target in targets:
		if not target.startswith('http://') and not target.startswith('https://'):
			target='http://'+target
		target = urllib.parse.urljoin(target,'/favicon.ico')
		perms.append(target)
		
	return perms

with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
	print(YELLOW + "generating permutations......"+ CLEAR)
	perms=generatePerms(targets)		
	print(YELLOW + "generated "+str(len(perms))+" permutations"+ CLEAR)
	try:
		executor.map(checkAll, perms)
	except(KeyboardInterrupt, SystemExit):
		print(RED + "[!] interrupted" + CLEAR)
		executor.shutdown(wait=False)
		sys.exit()

if inputs.output:
	result.sort()
	with open(output, 'a') as f:
		f.writelines("%s\n" % line for line in result)
print(YELLOW + "done"+ CLEAR)