# Hunter (HSM)
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/253c45cb-e1cd-45f6-a40d-1917003c50d6" />


# Objective

You are an operator for the **Hack Smarter Red Team**, currently conducting a black-box assessment on a client's external login portal. As part of the initial reconnaissance phase, our OSINT analysts have compiled a list of potential usernames.

You need to identify which one is a valid username for the web application.

# Recon

- I first run initial recon using `RustScan` to enumerate the available ports and get versions I can check for known vulnerabilities
- Then I run `Dirsearch` to find any directories, including hidden ones, that my provide vulnerable endpoints.

## NMAP

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0:00:04:f4:c2:df:4e:4f:31:19:21:db:81:80:5e:29 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGm43huw+gO+Whilj/5bkh2pvWLlV1UXQOSH6VNTE/fClcGa2cvPfyIQY4+BxiQHrA+pxneJLOAdy19VRhtoe4Q=
|   256 64:71:5d:80:b0:8d:20:a1:92:8e:c5:96:57:8b:ea:4e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGA2h68zPZ31D9kz84O8fxR5A40l616nJsZ+bGyyOvko

80/tcp open  http    syn-ack ttl 62 Werkzeug httpd 3.1.4 (Python 3.10.12)
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-server-header: Werkzeug/3.1.4 Python/3.10.12
|_http-title: HackSmarter Portal - Login
```

- Running `NMAP` with `RustScan` revealed 2 open ports: SSH(22) and HTTP(80)
- No significant vulns related to the versions were found

## Dirsearch

```bash
┌──(taako㉿kali)-[~/CTF/Hunter-HSM]
└─$ sudo dirsearch -u http://hunter.hsm                                                                                                 
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/taako/CTF/Hunter-HSM/reports/http_hunter.hsm/_26-02-26_19-15-09.txt

Target: http://hunter.hsm/

[19:15:09] Starting:                                                                                   
[19:15:57] 405 -  153B  - /login                                            
[19:16:14] 200 -    2KB - /reset                                            
                                                                             
Task Completed     
```

- 2 directories on the HTTP: `login` and `reset`

# Enumeration

- First, I checked the SSH authentication method
- Then I checked the HTTP `login` and `reset` pages to find potential vulnerable endpoints

## SSH (22)

```bash
┌──(taako㉿kali)-[~/CTF/Hunter-HSM]
└─$ ssh root@hunter.hsm      
The authenticity of host 'hunter.hsm (10.0.26.185)' can't be established.
ED25519 key fingerprint is: SHA256:GUZvPBwSijZP3ZgEU47n/HUfnUFcfzxTYBwcVzAaM2U
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'hunter.hsm' (ED25519) to the list of known hosts.
root@hunter.hsm: Permission denied (publickey).
```

- SSH uses token based authentication (good for security)

## HTTP (80)

I tried test:tester as `login` creds with `burpsuite`and got no unique response from the server. Fuzzing usernames through this page will not provide any hints.

<img width="853" height="571" alt="image" src="https://github.com/user-attachments/assets/037cd558-4653-471d-a7dc-5dc775e6e421" />


Tried test as the username on `reset` page and got “If an account matches that username, a reset link has been sent to the email on file.” This is the page to try fuzzing usernames on.

### TurboIntruder

<img width="1280" height="840" alt="image" src="https://github.com/user-attachments/assets/15fc506f-6c4f-41b1-96e0-a3b03b635118" />


I ran `TurboIntruder` extension in `Burpsuite` to attack the `reset` page.

<img width="1280" height="840" alt="image" src="https://github.com/user-attachments/assets/56cf09fe-737c-4b7c-b3fc-8e0ce142c7a9" />

- I initially looked for a different status code but all jobs return 200 (success) codes.
- Suspecting time-based enumeration could lead to clues, I sorted the jobs by time and saw that the `joey` user took nearly 5x the time to complete.
    - I assume the page is checking username before responding, so if the username matches something the database, it is running the email job before responding, leading to valid usernames to take longer to process.

# Flag Captured: `joey`

<img width="927" height="144" alt="image" src="https://github.com/user-attachments/assets/71d147f9-b42a-44a4-8a3d-eead50d0aa64" />


# How to prevent this vulnerability:

- This is a Time-based enumeration vulnerability.
- Making the response the same for valid and invalid was a great first step in securing this form, but the weakness comes from the difference in the code that runs.
- Option 1: To improve security, try standardizing the time scale for both requests by adding artificial wait times to all requests.
    - Delaying all requests to 2000ms, would ensure valid and invalid responses would be indistinguishable by time-based enumeration.
- Option 2: Since the response from the server is the same for both valid and invalid, send the response before validating the user.
    - By sending the response first, the time-based enumeration would not see a difference between a valid and invalid submission.
