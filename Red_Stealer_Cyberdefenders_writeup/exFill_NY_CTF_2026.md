
# 🔍 **Writeup task "exFill" | New Year CTF 2026**

</div>

## 📋 **Description**

> *Sniffers on the network can sometimes tell a lot*

**Task Files:**
- `capture.pcap`

**Flag format:**
Grodno{}
## Solution
So, let's analyze a capture.pcap file and understand, what happened:
### **1. Overview of the Network Environment**
- **Local network subnet**: `192.168.56.0/24`
- **Key hosts**:
  - `192.168.56.102` – Likely an attacker or scanning machine.
  - `192.168.56.103` – Likely the target machine (named *METASPLOITABLE*, a known vulnerable VM).
  - `192.168.56.100` – Another host on the network (possibly a client).
  - `127.0.0.1` – Loopback traffic (local services on a host).
- **Protocols observed**: TCP, UDP, ARP, DHCP, FTP, SSH, SMTP, HTTP, SMB, MySQL, VNC, RPC, NetBIOS, TLS, and others.

---

### **2. Observed Network Activities**

#### **a. ARP Activity (Address Resolution Protocol)**
- Frequent ARP requests/replies between `.102` and `.103`.
- Purpose: Mapping IP addresses to MAC addresses for LAN communication.

#### **b. TCP Connections & Service Probing**
The attacker (`192.168.56.102`) is actively scanning and interacting with multiple services on the target (`192.168.56.103`):

- **Port 6200** – Possible backdoor or remote administration service. Long-lived TCP session with data transfer.
- **Port 21 (FTP)** – Multiple FTP connection attempts with various usernames and passwords. Some responses show `530 Please login` and `421 Timeout`.
- **Port 22 (SSH)** – SSH version exchange (`SSH-2.0-OpenSSH_4.7p1`).
- **Port 25 (SMTP)** – SMTP service interaction, including `EHLO`, `STARTTLS` commands.
- **Port 80 (HTTP)** – Web server requests (`GET /`, `GET /favicon.ico`, `GET /robots.txt`, `OPTIONS /`). Server responds with `200 OK` and `404 Not Found`.
- **Port 111 (Portmapper)** – RPC service enumeration (`V2 DUMP`, `V3 DUMP`, `V4 DUMP`).
- **Port 139/445 (SMB)** – SMB protocol negotiation and session setup attempts.
- **Port 443 (HTTPS)** – TLS/SSL handshakes (`Client Hello`, `Server Hello`).
- **Port 3306 (MySQL)** – MySQL connection attempts (`Login Request user=`). Server greeting returned.
- **Port 5432 (PostgreSQL)** – Database service probes.
- **Port 5900 (VNC)** – VNC protocol version exchange (`RFB 003.003`).
- **Port 6000 (X11)** – X Window System connection attempt.
- **Port 8009 (AJP)** – Apache JServ Protocol traffic.
- **Port 4444** – **Notable**: Common Metasploit/Meterpreter reverse shell port. Large data transfers suggest possible payload delivery or command execution.

#### **c. UDP & Other Protocols**
- **UDP port 53 (DNS)** – DNS queries/responses.
- **UDP port 111 (Portmapper)** – RPC calls.
- **DHCP traffic** – `192.168.56.100` requesting/renewing IP.
- **BROWSER protocol** – NetBIOS browsing announcements from `METASPLOITABLE`.
- **NBNS** – NetBIOS Name Service registrations.
- **ICMP** – Destination unreachable messages (port unreachable).

---

### **3. Attack Patterns & Intrusion Indicators**

#### **a. Service Enumeration & Brute-Force Attempts**
- Systematic scanning of open ports and service interaction.
- FTP shows multiple failed logins, suggesting brute-force or credential guessing.
- SMTP and SSH protocol negotiation for banner grabbing or version detection.

#### **b. Exploitation Attempts**
- **Port 4444 activity**: High-volume data transfer from `.103` to `.102`. Suspicious for reverse shell or data exfiltration.
- **Multiple RST packets**: Indicate failed connection attempts or closed ports.
- **FTP with strange commands**: Username `3FVka:)` may be an attempt at command injection.
- **SMB authentication attempts**: `NTLMSSP_NEGOTIATE` and `NTLMSSP_AUTH`, suggesting attempts to access Windows shares.

#### **c. Post-Exploitation & Lateral Movement**
- Possible command execution and data transfer via port 4444.
- Network discovery via NetBIOS and SMB protocols.
- Long-lived TCP session on port 6200 (possible backdoor).

So, let's check last TCP packages ( и тут картинка где 3804 пакет и выше)

we can see that large packets were transmitted because segments: [PSH,ACK].
Ok, in that case let's follow TCP stream and look at it:
(фотка follow_TCP)
Easy to understand, that it's a base64 encode. So, let's decode it. For that we need to create a new file(let it be input.txt). 
(картинка decr1)
I pasted this BASE64 into input.txt and saved.
In my case I created this file on my Desktop. Then I wrote this:
(фотка команда декода базы 64)
And we see that there is a file output.png ( I saw it on my Desktop)
(фотка ёлочки)
We see this interesting christmas tree. But we need to find a flag grodno{}. 
In that case let's find some strings from this picture.
(Фотка скрипта)
And if to scroll down we will see a flag:
(фотка флага)

