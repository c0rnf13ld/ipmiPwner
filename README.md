# ipmiPwner
This exploit dump the user hash provided through the use of ipmitool

The script has by default a list of most common users so if no valid user is provided the script will default to the list of most common users, although it can also provide a list of users 

## Usage:

- ./requirements.sh
- python3 ipmipwner.py -h

## Parameters:
- --help   : Displays the help panel


**Required Arguments**


- --host   : The host of the target


**Cracking Arguments**


- -c       : Choose an option to crack the hash, the -pW and -oH is required for this option, options: john | python
- -uW      : The user wordlist to use, this is enabled by default if the user is False since the program has a small users dictionary by default.
- -pW      : The password wordlist to crack the hash, This parameter is required if cracking parameter is enabled
- -oH      : Output hash file, This parameter is required if cracking parameter is enabled
- -oC      : Output cracked hash file, This parameter is required if cracking with python is used.


**Optional Arguments**


- -p       : The port where the service runs, by default: 623
- -u       : Valid user to extract the hash
- -d       : Delay between each request in case of errors, by default: 20
- -r       : User validation attempts in case of errors, by default: 2

## Examples:
```
python3 ipmipwner.py --host 192.168.1.12 -c john -oH hash -pW /usr/share/wordlists/rockyou.txt
python3 ipmipwner.py --host 192.168.1.12 -oH hash
python3 ipmipwner.py --host 192.168.1.12 -uW /opt/SecLists/Usernames/cirt-default-usernames.txt -oH hash
python3 ipmipwner.py --host 192.168.1.12 -u root -c john -pW /usr/share/wordlists/rockyou.txt -oH hash
python3 ipmipwner.py --host 192.168.1.12 -p 624 -uW /opt/SecLists/Usernames/cirt-default-usernames.txt -c python -pW /usr/share/wordlists/rockyou.txt -oH hash -oC crackedHash
```
