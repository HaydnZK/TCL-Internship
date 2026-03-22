

# Wi-Fi Traffic Analysis & Credential Exposure Lab
## Project Summary
This lab focuses on capturing and analyzing network traffic to understand the difference between secure and insecure communication. I used Wireshark on my Ubuntu VM to monitor data as it leaves the interface. The goal's to identify how unencrypted protocols like HTTP expose sensitive data while HTTPS protects it. I started a packet capture and navigated to Altoro Mutual to perform login attempts on both the HTTP and HTTPS versions of the site. This setup allows me to see exactly what an attacker would see if they were sniffing the network.

---

## HTTP Traffic Analysis and Cleartext Breakdown
I performed a deep dive into the unencrypted HTTP packets to document exactly what's exposed during an insecure session. Unlike the TLS capture, the HTTP data's entirely transparent, allowing an analyst to see every detail of the user's interaction with the web server. When looking at the "POST /doLogin" packet, the lack of encryption means all the session metadata and the actual payload are visible to anyone sniffing the traffic.

### HTTP Packet Data Breakdown
The following breakdown shows the specific information I've identified within the packet layers of the unencrypted login attempt.
- **Frame Section**
    - Displays the total bytes captured on the wire.
    - Includes the frame number, arrival time, and encapsulation type.
- **Linux Cooked Capture v1**
    - Shows the packet type and confirms the protocol's IPv4.
    - Identifies the source MAC address and address length.
- **IPv4 Section**
    - Reveals the source and destination IP addresses.
    - Lists the header length, protocol type, and total packet length.
- **Transmission Control Protocol**
    - Shows the source and destination port numbers (typically port 80 for HTTP).
    - Displays the sequence numbers, acknowledgment numbers, and TCP flags.
- **Hypertext Transfer Protocol (HTTP)**
    - **GET/POST Request**: Identifies the specific action being taken, such as "/doLogin."
    - **Host** Shows the destination domain name in cleartext.
    - **User-Agent**: Reveals the browser and operating system information of the user.
    - **Accept/Accept-Language/Accept-Encoding**: Lists the types of data and languages the browser can handle.
    - **Referer**: Shows the URL of the previous page the user was on.
    - **Connection**: Indicates the status of the persistent connection.
    - **Cookie Information**: Displays session tokens or tracking cookies that could be used for session hijacking.
- **HTML Form URL Encoded**
    - This is where the actual sensitive data's located.
    - Shows the cleartext key-value pairs for the login, specifically revealing the username and password.

---

## HTTPS Traffic Analysis and Encryption Comparison
For the second part of the investigation, I've analyzed the same login attempt performed over a secured connection. Scrolling through the capture, I've identified a large volume of TLSv1.2 traffic in the protocol column. I've noted specific packets referencing cipher change specs and encrypted handshake messages. Upon closer examination, there's clearly no sensitive information present like there was in the HTTP capture. There's no message data from the login taking place, and when following the TCP stream, it shows only a few minor details in cleartext while the rest is encrypted garble. This proves that even though the packet's captured, the actual payload's protected from the attacker.

### Packet Data Breakdown
While the sensitive credentials are hidden, I've analyzed the packet headers to see what metadata's still visible to an analyst.
- **Frame Section**
    - Displays how much data's being sent on the wire.
    - Includes basic information like the frame number and encapsulation type.
- **Linux Cooked Capture v1**
    - Shows the packet type and protocol type (IPv4).
    - Identifies the source MAC address, address type, and address length.
- **IPv4 Section**
    - Reveals the source and destination IP addresses.
    - Lists the header length, protocol type, checksum, and total length.
- **Transmission Control Protocol**
    - Shows the source and destination port numbers.
    - Displays ACK numbers, sequence numbers, flags, and checksums.
    - Includes timestamps and other basic flow information.
- **Transport Layer Security (TLS)**
    - Identifies the content type, version, and length.
    - Confirms the payload's encrypted application data, appearing only as jumbled nonsense.

---

## DNS Analysis and Metadata Visibility
I've analyzed the DNS traffic to see how an attacker can profile a user's activity even before a connection's established. Since DNS primarily utilizes UDP, the packets are smaller and faster, but they're also unencrypted by default. By filtering for **dns** in Wireshark, I've identified the specific queries made to resolve the IP addresses for "demo.testfire.net" and "google.com."

### DNS Packet Data Breakdown
The following breakdown shows the metadata visible during the name resolution process.
- **Frame/Linux Cooked Capture/IPv4**
    - These sections remain consistent with the previous captures, providing the physical and logical addressing for the VM.
- **User Datagram Protocol (UDP)**
    - Shows the source and destination ports (DNS uses port 53).
    - The payload's noticeably smaller than TCP because UDP's connectionless and doesn't require the same overhead for sequencing or acknowledgments.
- **Domain Name System (DNS)**
    - **Transaction ID**: Used to match queries with responses.
    - **Flags**: Indicate if the packet's a query or a response.
    - **Questions & Answer RRs**: Shows the number of queries and returned records.
    - **Authority & Additional RRs**: Provides info about the name servers and extra resource records.
    - **Queries**: This is the most critical part, as it shows the actual domain name being requested (e.g., demo.testfire.net) in cleartext.

## Mitigation and Defense Strategies
To protect against the vulnerabilities identified in this lab, I've outlined several defenses that'd prevent credential exposure and metadata leakage.
- **Enforce HTTPS and HSTS**: Ensuring all web traffic's encrypted makes the cleartext POST attack impossible. HSTS forces the browser to ignore insecure HTTP versions of a site.
- **DNS over HTTPS (DoH)**: To prevent the metadata leakage seen in the DNS analysis, DoH encrypts the domain queries, hiding the user's browsing history from the network level.
- **Network Segmentation**: Implementing port security and VLANs would make it much harder for an attacker to join the local network and capture this traffic in the first place.

---

## Risks Associated with Metadata and Encrypted Traffic
While HTTPS protects the what (the password), it doesn't fully hide the who, where, or how much. An attacker or a malicious insider can use the visible metadata to build a highly accurate profile of user behavior.

### Risks of Visible Metadata
Even when I've got encryption turned on, I've identified several ways an attacker can still profile my activity.

- **Traffic Pattern Analysis**: By looking at the size and frequency of the "Encrypted Application Data" packets, an attacker can guess what kind of activity's happening. For example, a steady stream of large packets might indicate a file exfiltration in progress, even if the file's contents are hidden.
- **Service Identification (SNI Leakage)**: During the TLS handshake, the Server Name Indication (SNI) often sends the hostname in cleartext. This means an attacker knows exactly which service or cloud bucket (like an AWS S3 bucket) the `system` account's communicating with.
- **Endpoint Profiling**: The User-Agent and TCP fingerprinting allow an attacker to know the exact OS and browser version of the "root" user. If they see you're using an outdated Ubuntu version, they'll know which specific kernel exploits to try next.
- **Internal Reconnaissance**: Visible source and destination IP addresses allow an attacker to map the internal network topology, identifying which machines are "talkers" and where the most valuable data likely resides.

## Relevant ISO 27001:2022 Annex A Controls
Since you're looking for professional standards to back this up, several Annex A controls directly address the vulnerabilities we've identified in this lab.

| Control ID | Control Name | Relevance to My Lab |
|------------|-----------------|------------------------|
| **A.8.24** | Use of Cryptography | I've proven that without this, my credentials (eviluser) are sent in cleartext. I'm using this to show why enforcing TLS's a non-negotiable requirement for our web apps. |
| **A.8.20** | Network Security | This is the core of my packet capture. It's how I'm monitoring the "wire" to see unauthorized data transfers and identifying where my network's leaking metadata. |
| **A.8.21** | Network Segregation | If I'd had better segregation, my eviluser wouldn't have been able to sniff the traffic of the haydn account so easily. I'm highlighting this to show how to stop lateral movement. |
| **A.8.3** | User Endpoint Devices | Since I'm running this on an Ubuntu VM, I'm focusing on how I'd secure the actual host to prevent someone from just installing Wireshark and capturing my data. |
| **A.8.15** | Logging | I'm using the DNS and HTTP hits I've found to explain what kind of telemetry I'd want sent to my Splunk instance for real-time alerting. |

## Potential Uses for Visible Information
* **Social Engineering**: Knowing the specific banking portal (Altoro Mutual) a user visits allows an attacker to craft a much more convincing phishing email.
* **Targeted Exploitation**: Identifying the protocol versions (like TLS 1.2 vs 1.3) tells an attacker if the connection's vulnerable to older downgrade attacks.
* **Exfiltration Monitoring**: Tracking the "Total Length" in the IPv4 header helps an attacker confirm if their data theft's successful without needing to see the data itself.
