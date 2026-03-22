# WPA2 vs WPA3 Security Architectures 
## Summary
This research task's focus centers on the evolution of Wi-Fi Protected Access (WPA), specifically how the industry moved from the aging WPA2 standard to the more robust WPA3. While WPA2 served as the backbone of wireless security for over a decade, vulnerabilities like the KRACK (Key Reinstallation Attack) necessitated a structural overhaul.

---

## WPA2
WPA2 was formally ratified by the IEEE as the 802.11i standard in June 2004. It's a secure wireless security protocol that's intended to aid in the protection of Wi-Fi networks through the use of strong encryption standards (AES). This came as an improvement to the old standards, WPA and WEP, and added strong data protection for devices on both home and business networks. Despite the fact that it was superseded by WPA3, WPA2 is still widely used in many networks today, as its security is still strong. 

### WPA2: Improvements
There were a number of improvements that WPA2 made, including the mandate for stronger encryption as opposed to the previous WPA's use of Temporal Key Integrity Protocol (TKIP). The main improvements WPA2 made include: 
- **Mandatory AES Encryption**: AES was the new mandatory cipher model for WPA2, which improved upon the previous TKIP. 
- **Stronger Security (CCMP)**: On top of AES encryption, WPA2 also utilized CCMP (Counter Mode Cipher Block Chaining Message Authentication Code Protocol) to provide strong protection, confidentiality, and integrity. 
- **WPA2-Enterprise**: Through the use of IEEE 802.1X/RADIUS servers for individual credentials rather than a shared password, businesses received a massive upgrade with WPA2. 
- **Increased Performance**: On top of being more robust, AES is also much more efficient on modern hardware as opposed to TKIP. 
- **Improved Key Management**: WPA2 introduced dynamic, per-user and per-session keys to improve the key management process. 

### WPA2 Personal: Authentication Flow
WPA2 authentication utilizes a four-way handshake in order to verify credentials in a secure manner while generating an encryption key without transmitting the password. The client and the AP use a shared passphrase to create the Pairwise Master Key (PMK) before a 4-step exchange (ANonce, SNonce) to create a session-specific Pairwise Transient Key (PTK). There are two separate flows for WPA2 authentication:

1. **WPA2-PSK**
- **Discovery**: First, the client (station) discovers the AP and sends an association request. 
- **Four-Way Handshake**
  - **Msg 1 (AP to Client)**: AP sends a random number (ANonce).
  - **Msg 2 (Client to AP)**: Client creates a random number (SNonce), computes the PTK (key derived from PMK, ANonce, SNonce, and MACs), and sends SNonce and a Message Integrity Code (MIC) to the AP. 
  - **Msg 3 (AP to Client)**: AP then validates the MIC, computes the PTK, and sends the group key to the client. 
  - **Msg 4 (Client to AP)**: Client confirms the keys are installed, and encrypted communication can begin. 

2. **WPA2-Enterprise (802.1X)**
- **Association**: The client associates with the AP, but blocks network access. 
- **EAP Exchange**: The client (supplicant) communicates with a RADIUS server (authentication server) through the AP (authenticator) via EAPOL frames to authenticate credentials. 
- **Key Generation**: Once successfully authenticated, the RADIUS server sends the PMK to the AP and the 4-way handshake can occur as seen above.

### WPA2: Vulnerabilities 
There are a couple of vulnerabilities associated with WPA2, with the primary one being the KRACK (Key Reinstallation Attacks) exploit. The majority of WPA2 implementations are vulnerable to these attacks that bypass encryption.

#### **KRACK Vulnerabilities (CVE-2017-13077/13088)** This pair of vulnerabilities targets the 4-way handshake and gives a threat actor the ability to bypass encryption if they're within range. A few things to note are:
1. **The Attack**: Attacks that exploit these vulnerabilities target the 4-way handshake. This is how the typical chain looks:
  1. **Placement**: A threat actor positions themselves in range of the Wi-Fi network they're targeting. 
  2. **Interception**: The threat actor waits for client devices to begin handshakes with the AP. 
  3. **Manipulation (Third Step)**: The third message of the handshake is intercepted and blocked from reaching the client. 
  4. **Forced Retransmission**: After not receiving a response, the AP sends the third message again. The threat actor facilitates this multiple times.
  5. **Nonce Reset**: This process can trick the client device into reinstalling an already-in-use encryption key, therefore resetting the cryptographic nonce to zero. 
  6. **Exploitation**: Through this process, the threat actor gains the ability to decrypt, replay, and forge network traffic. 

2. **Impact**
- **Data Interception**: A threat actor's capable of decrypting sensitive information; this can include passwords, credit card numbers, and private messages.
- **Data Manipulation**: Certain configurations (such as WPA-TKIP or GCMP) can facilitate the injection of malicious data or ransomware into websites. 
- **Widespread Reach**: Because this is a protocol-level flaw, the majority of WPA2-compliant devices were vulnerable across different manufacturers, though it hit Android and Linux the hardest. Some versions could be forced to install all-zero encryption keys, which essentially removes encryption. 

3. **Mitigation**
There's a few mitigation techniques for this set of vulnerabilities, including:
- **Software Patches**: The latest security updates should be installed in a timely manner for all client devices and router firmware. 
- **Upgrade to WPA3**: A WPA3 transition should be considered, as it's intended to be immune to key reinstallation attacks. 
- **Use a VPN**: All traffic should use a trusted VPN to encrypt data and provide an extra layer of security, even if Wi-Fi encryption's bypassed. 
- **Enforce HTTPS**: All web traffic should utilize HTTPS only to protect sensitive data in the application layer. 

#### **Hole196 Vulnerability** If a threat actor has the network password, they can use the GTK (Group Temporal Key) to decrypt traffic from other users as well as launch attacks. 
1. **The Attack**
As an insider attack, this one exploits the way group keys are handled within WPA2. The attack chain typically looks like this:
  1. **Authentication**: The attacker must already be an authenticated user on the network. 
  2. **GTK Abuse**: Each authorized user has access to the GTK (Group Temporal Key), which is used for broadcast traffic. 
  3. **Spoofing**: The threat actor can use this GTK to spoof broadcast packets, making them appear to come from the AP.
  4. **Poisoning**: A target device is sent a spoofed ARP packet on the same network. 
  5. **Interception**: The target device's ARP cache is then poisoned; this results in the device sending its private traffic to the attacker's MAC address instead of the legitimate gateway. 
  6. **MitM**: Now, the threat actor can sniff, decrypt, and manipulate the victim's traffic. 

2. **Impact**
- **Insider Man-in-the-Middle (MitM)**: Malicious, authorized users can spoof the AP and send GTK-encrypted ARP packets to other clients, which poisons their ARP caches. This can redirect traffic through the threat actor's device. 
- **Privacy Breach**: In enterprise networks that use WPA2 where each user has a unique private key, insider threats can bypass isolation and sniff or decrypt traffic from other users. 
- **Denial of Service (DoS)**: Threat actors can use this to bolster their broadcast packet numbers, which forces legitimate messages from the actual AP to be dropped as replays by other clients. 

3. **Mitigation**
There are a number of ways to mitigate against this vulnerability, including:
- **Client Isolation**: Client or AP isolation should be enabled on wireless controllers to help prevent connected devices from communicating directly with each other. 
- **Wireless Intrusion Prevention (WIPS)**: A WIPS solution should be deployed to help detect and block spoofing and ARP poisoning attempts. 
- **Unique Group Keys**: Enterprise-grade hardware that's capable of providing unique group keys to each client should be used; this neutralizes the shared-key vulnerability.
- **Network Segmentation**: The use of VLANs to isolate groups of users should be implemented to help limit the reach of a threat actor.

---

## WPA3
WPA3 is the latest Wi-Fi security standard and was introduced as a replacement for WPA2. WPA3 offers enhanced protection through stronger encryption (192-bit), robust password protection (SAE protocol), and bolstered security for public networks. WPA3 fixes the vulnerabilities discussed above that plagued WPA2, particularly in modern Wi-Fi 6/7 devices. 

### WPA3: Improvements
There's a number of improvements that were made over WPA3's predecessor, WPA2. These include:
- **Simultaneous Authentication of Equals (SAE)**: A replacement for WPA2's PSK exchange; this makes it much more difficult for threat actors to crack passwords through offline dictionary attacks. 
- **Forward Secrecy**: Even if a threat actor discovers a network password, they cannot decrypt previously captured traffic with it. 
- **192-bit Security (Enterprise)**: This bolsters the cryptographic strength for high-security, sensitive networks. 
- **Protected Management Frames (PMF)**: This helps prevent eavesdropping and deauthentication attacks, strengthening connection stability. 
- **Wi-Fi Enhanced Open**: This uses OWE (Opportunistic Wireless Encryption) to provide individualized data encryption on open, public Wi-Fi hotspots; this protects users without requiring a password. 
- **Wi-Fi Easy Connect**: This simplifies the secure onboarding of IoT devices without displays by scanning a QR code. 

### WPA3: Authentication Flow
WPA3 comes in personal and enterprise editions, much like WPA2. WPA3 offers a variety of improvements in the authentication flow to make it more resistant to threat actors. 

1.  **WPA3 Personal: Authentication Flow**
  1. **SAE Commit Request (Client > AP)**: The client sends a "commit" message that contains a public key (derived from ECC/Diffie-Hellman) that's bound by the password. 
  2. **SAE Commit Response (AP > Client)**: The AP responds with its own commit message; this results in both sides being able to calculate a shared secret, though it's not confirmed yet. 
  3. **SAE Confirm Request (Client > AP)**: The client sends back a confirmation message to verify that the calculated secret is the same on both sides; this ensures the password is correct. 
  4. **SAE Confirm Response (AP > Client)**: The AP confirms the exchange and completes the SAE authentication. 
  5. **Association & 4-Way Handshake**: Once the SAE exchange is complete, the devices continue to association and the standard 4-way handshake to generate session-specific keys for data encryption. 

2.  **WPA3 Enterprise: Authentication Flow**
The enterprise edition utilizes the IEEE 802.1X framework for secure, certificate-based (or credential-based) access. This frequently uses EAP-TLS for mutual authentication and enforces mandatory Protected Management Frames (PMF) and robust encryption. The process looks like this: 
  1. **Discovery**: The client device scans and selects the WPA3-Enterprise SSID. 
  2. **802.1X/EAP Negotiation**: The client and RADIUS server negotiate authentication methods (such as EAP-TLS) through the AP. 
  3. **Tunnel Establishment**: A secure TLS tunnel's established for the exchange of credentials and certificates. 
  4. **Verification**: The RADIUS server verifies the client's certificate or credentials. 
  5. **Key Generation & Access**: Once complete, the server sends a success message, and both parties derive a PMK for encryption. 
  6. **Data Transmission**: The connection's then encrypted through AES-GCMP/CCMP (Galois/Counter Mode Protocol/Counter Mode with Cipher Block Chaining Message Authentication Code Protocol).

### WPA3: Vulnerabilities 
While WPA3 is a major upgrade in security, it's not without flaws. There are several vulnerabilities that were discovered in the early days of WPA3 implementations; these include:
- **Dragonblood (SAE Handshake Flaws)**: There have been attacks on the SAE handshake as well as the Dragonfly key exchange; this can allow for password recovery. 
- **Downgrade Attacks**: A threat actor can force devices to use WPA2 or other legacy protocols, therefore bypassing the protections WPA3 provides. 
- **Side-Channel Attacks**: Information's divulged to threat actors by analyzing timing and memory usage during the handshake. 
- **Rainbow Table/Cloud Attacks**: Weak passwords can still be targeted with cloud computing and pre-computed tables, though this's less common than it was on WPA2. 
- **Mixed Mode Risks**: Routers that support both WPA2 and WPA3 (mixed mode) for compatibility remain vulnerable to attacks against WPA2. 

### WPA3: Mitigations
WPA3's quite strong despite the vulnerabilities it faces, but there are still a few things you can do to help mitigate potential threats. These include:
- **Strong Passwords**: It's vital to use strong, complex passwords or passphrases to help mitigate brute-force attempts. 
- **Firmware Updates**: The latest security patches should be applied to routers and other devices in a timely manner. 
- **Disable Mixed Mode**: On devices that support it, you should solely use WPA3-only mode.
