#!/usr/bin/python3

import hashlib, hmac, os, sys, signal, argparse, re, time

def arguments():
	parser = argparse.ArgumentParser()
	req = parser.add_argument_group("Required arguments")
	req.add_argument("-f", "--file", help="The file with the hash", dest="file", metavar="/path/to/file", required=True)
	req.add_argument("-w", "--wordlist", help="The wordlist of passwords to crack the hash", dest="wordlist", metavar="/path/to/password_wordlist", required=True)
	req.add_argument("-o", "--output", help="File where the cracking result will be saved", dest="output", metavar="/path/to/output", required=True)
	parser.add_argument("-l", "--line", help="Notify when the specified number of lines has been read, by default: 100,000", dest="top", metavar="number", default=1000000, type=int)
	return parser.parse_args()

def checkArguments(file, output, wordlist):
	if not os.path.isfile(file):
		print(f"[!] The file: {file} does not exist"); sys.exit()

	if not os.path.isfile(wordlist):
		print(f"[!] The wordlist: {file} does not exist"); sys.exit()

def readHashFile(file):
	with open(file, "r") as f:
		content = f.read()
	if "$rakp$" not in content:
		print("[!] Wrong hash format")
		print("[*] The hash must be in this format:\n$rakp$salt$hash"); sys.exit()
	salt = re.findall(r"\$rakp\$(.*)\$", content)[0]
	hash = re.findall(r"\$rakp\$.*\$(.*)$", content)[0]
	return hash, salt

def readByChunks(file, wordlist, chunk_size=1024 ** 2):
	content = b""
	full_size = os.path.getsize(wordlist)
	print("[*] Reading the wordlist by chunks")
	print(f"[*] Chunk size: {chunk_size}")
	while True:
		file_content = file.read(chunk_size)
		if not file_content:
			return content
		else:
			content += file_content
		print(f"[*] Reading Bytes: {str(len(content))}/{str(full_size)}" + " " * 50, end="\r")

def crack(hash, salt, password):
	hashed = hmac.new(password, salt, hashlib.sha1).hexdigest()
	if hashed == hash:
		return 1, password, hashed
	else:
		if not hashed:
			print("[*] Something went wrong"); sys.exit()
		return 0, password, hashed

def save(output, time, password, hash, salt):
	with open(output, "a") as f:
		f.write(f"$rakp${salt}${hash}:{password}\n")
		f.write(f"Time elapsed: {time}\n")
		f.close()

def main():
	args = arguments()
	file, output, wordlist, top, init_top = args.file, args.output, args.wordlist, args.top, args.top

	checkArguments(file, output, wordlist)
	hash, salt = readHashFile(file)
	salt_bytes = bytes.fromhex(salt)
	f = open(wordlist, "rb")
	wordlist_content = readByChunks(f, wordlist).decode(errors="ignore").split("\n"); f.close(); print()

	start = time.time()
	count = 0
	print("[*] Hash Cracking Started")
	for password in wordlist_content:
		valid, passwd, hashed = crack(hash, salt_bytes, password.encode())
		count += 1

		if count == top:
			print(f"[*] {count} lines of the wordlist have already been read.")
			top += init_top

		if valid:
			end = time.time()
			print(f"[+] Password Found, Cracked on line: [{count}]")
			print(f"[+] The password: {passwd.decode()}")
			final = end - start
			print(f"[+] Time elapsed: {round(final, 5)}")
			save(output, round(final, 5), passwd.decode(), hash, salt)
			print(f"[+] Result saved in: {output}")
			sys.exit()
	print("[*] No Match Found"); sys.exit()

def def_handler(signum, frame):
	sys.exit()

signal.signal(signal.SIGINT, def_handler)

if __name__ == '__main__':
	main()
