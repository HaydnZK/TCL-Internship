# The Timeline of Ransomware
## Description 
This research study analyzes the evolution of ransomware from its 1989 origins to modern cybercrime operations. It explores the technical shifts in encryption, the professionalization of Ransomware-as-a-Service (RaaS), and the transition from simple data locking to complex triple-extortion tactics.

---

## The AIDS Trojan (PC Cyborg): 1989

### 1. Overview
The AIDS Trojan was the first documented instance of ransomware and was created by biologist Joseph Popp. 

#### Origin and discovery
Joseph Popp created the AIDS Trojan and distributed it via 20,000 infected floppy disks. These were handed out to attendees at the World Health Organization (WHO) AIDS conference in Stockholm and sent through the mail via a subscription service list. The disks were labeled "AIDS Information - Introductory Diskettes." The physical packaging included leaflets warning that the software could have adverse effects on other applications and that users would owe compensation to the PC Cyborg Corporation. It explicitly stated that the microcomputer would stop functioning normally if the terms were not met.

#### Target industries
The AIDS Trojan targeted a very specific niche by focusing on the 1989 WHO AIDS Conference. Consequently, the majority of the victims were medical researchers, healthcare professionals, and doctors.

### 2. Attack Methodology
#### Initial access techniques
The distribution relied entirely on social engineering and physical media. Because the virus was only spread through floppy disks, Popp relied on the trust of the medical community. Despite the printed warnings regarding the potential impact on their systems, many users still installed the program.

#### Lateral movement
As a localized Trojan distributed via physical media, this variant did not possess capabilities for lateral movement or network propagation.

#### Encryption process
The malware utilized a logic bomb designed to trigger only after the infected computer had been booted 90 times. Once the threshold was met, the Trojan used QUICKBASIC 3.0 to hide directories and encrypt or "mung" the names of files on the C drive. It is important to note that the file contents themselves were not encrypted, only the file names. The process used simple symmetric cryptography, which made it a relatively easy fix. Decryption tools were released by the community shortly after the outbreak. Victims who could not access those tools were instructed to mail $189 to a PO Box in Panama belonging to the PC Cyborg Corporation to receive a decryption key.

### Indicators of Compromise (IoC)
- **Malicious Media:** Floppy disks labeled "AIDS Information - Introductory Diskettes."
- **Modified System Files:** Upon insertion and execution, the malware hijacked the AUTOEXEC.BAT file and modified it to track the system reboot count.
- **Reboot Threshold:** The malicious payload remained dormant until exactly 90 reboots were completed.
- **Directory Changes:** Activation resulted in hidden directories and scrambled, unreadable file names across the primary drive.
- **Ransom Message:** A full-screen ransom note appeared claiming the software lease had expired and demanding payment for a renewal kit.

### Special Features
- **Logic Bomb:** One of the earliest uses of a boot-count trigger for malware execution.
- **Symmetric Cryptography:** Used a simple substitution-style cipher that was eventually cracked without paying the ransom.

### Real-World Incidents
- **1989 WHO Conference:** The primary incident involved the mass distribution of these disks to delegates from over 60 countries, leading to significant data disruption for international medical research institutions.

Shortly after AIDS appeared, researchers released and distributed what they called "vaccines." These consisted of:
- **AIDSOUT:** This tool was created by Jim Bates and was designed to delete the trojan
- **AIDSCLEAR:** This program was created to retrieve and restore the hidden and encrypted files and directories. 

---

## The Birth of Cryptovirology: 1996
### 1. Overview
In 1996, Adam L. Young and Moti Yung established the field of Cryptovirology. They introduced this concept through the release of a seminal paper titled "Cryptovirology: Extortion-Based Security Threats and Countermeasures," which was presented at the 1996 IEEE Symposium on Security and Privacy.

#### Origin and discovery
This paper was released nearly a decade after the AIDS Trojan, which had relied on easily breakable symmetric cryptography. The research outlined new discoveries that could both advance security and empower malicious actors in the ransomware scene. This work served as the formal blueprint for the sophisticated and virtually unbreakable ransomware seen in the modern threat landscape.

### 2. Theoretical Foundations
- **Asymmetric Advantage:** By 1996, the advancement of public-key cryptography provided a massive advantage to attackers. The authors demonstrated that by using a public key to encrypt data, only the attacker, who holds the corresponding private key, could undo the damage. This eliminated the possibility of victims or researchers creating simple decryption tools as they had for the AIDS Trojan.
- **Cryptoviral Extortion:** The paper describes a theoretical foundation for modern ransomware. It explores the use of a computer virus that can encrypt a victim's data and demand a ransom in exchange for the decryption key, turning cryptography into a weapon for extortion.
- **Electronic Money:** Although it didn't yet exist in its modern form, the authors predicted that attackers would eventually demand payment through electronic money, such as cryptocurrencies, to maintain anonymity and facilitate global transactions.
- **Kleptography:** Alongside Cryptovirology, Young and Yung introduced the idea of Kleptography. This involves the study of stealing information securely and subliminally through the use of asymmetric backdoors hidden within cryptographic systems and protocols.

### 3. Impact on Evolution
- **Shift from Symmetric to Asymmetric:** This marked the transition from "munging" file names with simple keys to the permanent encryption of file contents.
- **Proactive Defense:** The paper also proposed countermeasures, urging the security community to recognize that encryption could be used as a tool for harm just as easily as it's used for protection.

---

## Gpcode (PGPCoder) & Archievus: 2005-2006
### 1. Overview
**Gpcode (PGPCoder):** This is a trojan that encrypts the files on a victim's computer and demands a ransom in order to release them. Although early versions contained flaws that made them easy to crack, Gpcode was recognized as the first ransomware to use asymmetric encryption in the wild. 

**Archievus:** This was a virus created for Windows operating systems and used as a method of extortion. While much smaller in scale than Gpcode, it was also one of the pioneers of ransomware using asymmetric encryption. Much like Gpcode, Archievus contained flaws that made it easy to mitigate once the vulnerability was discovered.

#### Origin and discovery
**Gpcode (PGPCoder):** This malware is often associated with the misuse of Pretty Good Privacy (PGP) technology, which was created by Phil Zimmermann in 1991. There's no official attribution as to who created the virus, though it's believed to be related to Russian cybercriminals. The ransom notes were frequently written in Russian or poorly translated English, and early versions were discovered on Russian underground forums. 

**Archievus:** This appeared shortly after Gpcode in 2006. As with Gpcode, there is no definitive information on the author of the virus. 

#### Target industries
**Gpcode (PGPCoder):** While this did not target one specific industry exclusively, Gpcode primarily targeted white collar professionals and business environments. 

**Archievus:** Archievus didn't target specific industries; instead, it focused on targeting home computer users. 

### 2. Attack Methodology
Both malware families utilized different social engineering techniques to infect computers and employed asymmetric encryption to lock data. 

#### Initial access techniques
**Gpcode (PGPCoder):** The primary access vector for Gpcode was malicious spear phishing emails. These campaigns frequently targeted business users with social engineering lures such as fake job applications or invoices. 

**Archievus:** Archievus was primarily bundled with spam and freeware. It took advantage of drive by downloads, being one of the first to experiment with malicious websites forcing downloads through the browser. It was often hidden inside free utility software or screensavers downloaded from suspicious websites. 

#### Lateral movement
Neither Gpcode nor Archievus included any capabilities for lateral movement. At this time, malware was delivered through lone wolf infections. There was no automation for spreading through a network, as the simple goal was to hit one computer and receive one payment. Complex network wide attacks were not yet a feature of ransomware during this period. 

#### Encryption process
While both used asymmetric cryptography and RSA to lock files, the two malwares utilized different methods:

**Gpcode (PGPCoder):** This was a sophisticated program that recognized that RSA is computationally expensive and slow. As a workaround, it used a Hybrid Encryption Scheme achieved in three steps:
- **Symmetric Encryption:** For each file, Gpcode would generate a random symmetric key. It used a simple stream cipher in early versions and AES in later versions to quickly encrypt the actual data of photos and documents. 
- **Asymmetric Encryption:** To hide the symmetric key, Gpcode would take that session key and encrypt it with a stronger RSA public key hardcoded into the malware. 
- **The Ransom Note:** Once complete, Gpcode created a `ReadMe.txt` file in each folder explaining the situation and demanding a ransom. 

**Archievus:** This used a universal lock rather than generating unique keys for every victim. It used one hardcoded key for all infections. It would search for the `My Documents` folder and encrypt every file within it. Because it used a single 30 digit password (`987654321098765432109876543210`), decryption became easy for victims once the key was discovered. 

### 3. Indicators of Compromise (IoC)
**Gpcode:**
- **File Extensions:** Encrypted files typically append specific extensions to the original filename.
- **Ransom Notes:** The presence of files such as `ReadMe.txt` or `HOW_TO_DECRYPT.txt` appearing in multiple directories. 
- **Network Activity:** Outbound connections to unknown or malicious IP addresses associated with C2 servers, particularly in newer versions of the malware. 
- **File System Changes:** Large scale modifications, such as the creation of encrypted files and deletion of originals, and the presence of malicious executables in temporary or system folders. 
- **Registry Keys:** Modifications to `HKEY_LOCAL_MACHINE` and `HKEY_CURRENT_USER` to ensure the ransomware runs upon reboot. 
- **System Performance:** Large spikes in CPU and disk activity due to the intensive encryption process. 

**Archievus:**
- **Malicious Filename:** The executable was often named `archievus.exe`.
- **File Extension:** It appended the `.kdsk` extension to encrypted files.
- **Ransom Note:** It dropped a file named `How to get your files back.txt` into the `My Documents` folder.
- **Registry Keys:** It added a value to `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` to ensure the ransom note appeared at every login.

### 4. Special Features
**Gpcode:**
* **Evolution of Encryption:** Early versions utilized custom, flawed encryption, while later versions adopted robust algorithms like RSA-1024 and AES-256.
* **Data Overwriting:** A notable feature of the .ax variant is that it physically overwrites the original file once it is encrypted, making recovery through undeletion tools essentially impossible. 
* **File Deletion:** The `.ak` version would delete the original files after creating an encrypted version in a new location, which sometimes allowed for file recovery. 
* **Targeted File Extensions:** While early versions might impact a whole system, newer versions of Gpcode targeted specific file extensions. 

**Archievus:**
* **Targeted Encryption:** Specifically targeted files located only within the `My Documents` directory.
* **Extortion Method:** Rather than a direct payment, it uniquely instructed users to purchase items from designated websites to retrieve the decryption password. 
* **Password Requirement:** To unlock files, users had to enter a specific 30 digit password. 
* **Type:** Much like the AIDS ransomware, Archievus was a trojanized piece of malware. 

### 5. Real-World Incidents
**Gpcode:** 
* **The RSA Arms Race:** This was a famous cat and mouse game with researchers at Kaspersky. The author would release a version with 64 bit encryption; researchers would crack it, prompting the author to release 128 bit, then 256 bit, and eventually RSA-1024 versions. 
* **The Six Story Distributed Crack:** When the 1024 bit version (`.ak`) was released, it was so technically effective that the security community attempted a massive distributed computing project to crack the key. This was one of the first times a single piece of malware forced global researchers to collaborate on a large scale cryptographic problem. 
* **The $20 Home User Extortion:** Unlike modern ransomware demanding millions, Gpcode targeted home users for small amounts, usually around $20, through E-gold or Liberty Reserve. Most victims paid because the cost was lower than taking the computer to a repair shop. 

**Archievus:** 
* **The Affiliate Purchase Scheme:** Instead of a direct ransom, victims were directed to online pharmacies to buy medication. The attacker earned commissions on these sales, effectively outsourcing the payment processing to legitimate retail websites. 
* **The Universal Password Incident:** Because the attacker used the same password for every victim, a researcher discovered the 30 digit key and published it. This immediately neutralized Archievus infections and taught the security community about the vulnerabilities of hardcoded keys.

---

## WinLock (Trojan.Winlock): 2006-2007
### 1. Overview
Appearing around 2007, WinLock was one of the first widespread "locker" variants. Rather than encrypting data, it restricted access to the Windows user interface by displaying pornographic images or fake system warnings.

#### Origin and discovery
With ties to Russian cybercriminal groups, this malware was notable because it was one of the pioneers of utilizing "screen lockers" rather than encrypting the victim's files. This marked a move toward more extortionate, financially motivated malware as opposed to earlier, simpler Trojan-based extortions. 

#### Target industries
The early versions of this malware primarily targeted individual Windows users, particularly focusing on Russian-speaking markets initially. 

### 2. Attack Methodology
WinLock was distributed via social engineering like previous ransomware; however, unlike those witnessed prior, this focused on restricting access to the desktop rather than encrypting files. 

#### Initial access techniques
Though the attackers utilized social engineering to deliver the malware, there were several different methods, such as:
  - **Phishing Emails:** Attackers would use spam emails with malicious attachments or links, usually masquerading as legitimate files, such as:
    - Invoices
    - Job Applications
    - Greeting Cards
  - **Compromised Websites:** Users would be lured to malicious websites, occasionally through drive-by downloads, which would trigger the download of the malware without the user's consent. 
  - **Disguise:** Frequently, WinLock would be trojanized, posing as harmless applications, such as:
    - `Adobe Gamma Loader.exe`
    - `VXGame.exe`

#### Lateral movement
At this point in time, ransomware was still in its "lone wolf" phase; much like its predecessors, it would infect a single workstation, collecting one payment and moving on. 

#### Encryption process (System Locking)
Once WinLock was installed, it would not immediately encrypt files like previous ransomware. Rather, it would take over the Windows OS screen, which prevented users from accessing the desktop, taskbar, and files. Once locked, the malware would display an often pornographic image to harass the user and demand a ransom. In later variants, the screen would even claim to be from law enforcement or request "Windows Product Activation" keys to make the scam seem legitimate. 

### 3. Indicators of Compromise (IoC)
There are a handful of notable IoCs related to WinLock. Much like all ransomware, there is the effective locking out and ransom note, but some key IoCs for WinLock include:
  - **Modified Registration Keys:** `[HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon] 'SHELL' = 'Explorer.exe, Ixplorer.exe'`
  - **Modified File System:** `%WINDIR%\Ixplorer.exe`
  - **Window Title and Class Searches:** The malware searched for and suppressed the following windows:
    - ClassName: '' WindowName: 'Program Manager'
    - ClassName: '' WindowName: 'Registry Editor'
    - ClassName: '' WindowName: '???????? ???????'
    - ClassName: 'Shell_TrayWnd' WindowName: ''
    - ClassName: '' WindowName: '????????? ????? Windows'
    - ClassName: 'TaskManagerWindow' WindowName: 'Windows Task Manager'
  - **System Utility Disruption:** Early WinLock variants would terminate or block access to several systems, such as:
    - Task Manager (`taskmgr.exe`)
    - Registry Editor (`regedit.exe`)
    - Command Prompt (`cmd.exe`)
  - **Malicious File Activity:** Early WinLock variants would often drop files into system or temporary directories, such as:
    - Files in `%WINDIR%` or `%SYSTEM32%` (for example, `userinit.exe` replacements or random `.exe` files)
    - Temporary files in the `%TEMP%` directory

### 4. Special Features
As opposed to today's ransomware, early WinLock variants were much less complex; however, there are a few key features that are relevant to this malware, such as: 
  - **SMS-Based Extortion:** The main feature of WinLock was its payment method. Victims were told to send a premium-rate SMS to a specific shortcode to receive an unlock code. This enabled the attackers to collect small, automated payments without needing a complex banking structure. 
  - **Social Engineering and Scareware:** Many versions of WinLock used psychological pressure rather than encryption, such as:
    - **Pornographic Content:** The ransom note would frequently display a full-screen explicit image to embarrass the user into paying quickly.  
    - **Authority Impersonation:** Early variants would pose as a legitimate software alert, such as Windows Product Activation notices, or claim the system was not registered or legal. 
  - **System Integrity Locks:** Unlike modern ransomware, WinLock focused on locking the user out and preventing system usage through: 
    - Blocking Task Manager, Registry Editor, and Command Prompt to prevent manual removal. 
    - Creating a "top-most" window that would stay above all other elements, essentially blocking the UI. 

### 5. Real-World Incidents
This version of WinLock was characterized by high-volume, indiscriminate distribution rather than targeted attacks. Most of the victims of this ransomware were individual home users, as they were less likely to have robust backups or professional IT support. Notable real-world incidents include:
  - **The $16 Million Gang:** This was one of the more notable incidents involving a Moscow-based gang that operated WinLock. Upon their arrest in 2010, authorities revealed that the gang had extorted $16 million (approximately 500 million rubles) from roughly one million victims. 
  - **Widespread Infection:** It is suggested that hundreds of thousands of computers across Russia and Eastern Europe were infected at the peak of the campaign. This demonstrates how quickly small ransoms ($10 to $20) can accumulate.

---

## Reveton: 2010-2012
### Overview
Known as "FBI Ransomware" or the "Police Trojan," Reveton popularized the "Law Enforcement" lure. It built off of what WinLock started and would lock the screen with a localized message (claiming to be from the FBI or Metropolitan Police) accusing the user of viewing illegal content. Reveton is widely credited with establishing the Ransomware-as-a-Service (RaaS) business model. 

#### Origin and discovery
Created by Maksim Silnikau (Belarus), who operated under the alias "J.P. Morgan," the operation also involved Raymond Uadiale (USA/Nigeria), who was later convicted for laundering over $100,000 in Reveton payments. Reveton was originally discovered in Germany, localized as the "BKA" ransomware, before rapidly spreading across Europe and North America using localized templates for more than 24 countries. This was the first ransomware to infect users through heavily automated means. 

#### Target industries
Reveton was another ransomware that did not target specific industries, but rather targeted individual users. This malware relied on a "shotgun" approach, which cast a wide net to infect as many personal computers as possible through automated distribution. 

### Attack Methodology
Much like WinLock, this was another locker variant of ransomware; rather than encrypting the victim's files, it would lock the victim out of the computer and display a banner. Alongside the Reveton ransomware, the creator also utilized the Blackhole exploit kit as the primary delivery vehicle. 

#### Initial access techniques
Reveton was mostly distributed through malvertising on adult websites, as well as through the Citadel botnet and the Blackhole exploit kit. 

##### Blackhole Exploit Kit
The Blackhole exploit kit was a prominent, commercially sold software toolkit that automated the process of infecting a victim's computer by leveraging security vulnerabilities in outdated software like web browsers and their plugins. Active from around 2010 to 2013, it was a "crime-as-a-service" offered for rent on the dark web, lowering the barrier to entry for cybercriminals.

#### Lateral movement
At this point in time, ransomware was still in its "lone wolf" phase; much like its predecessors, it would infect a single workstation, collecting one payment and moving on. 

#### Encryption process (System Locking)
Much like WinLock, Reveton did not actually encrypt the user's data; rather, it would lock the user out of the UI and their OS. Once the user was locked out, a full-screen display would appear with a fake "legal notice." Later versions of the malware included some encryption, mostly to ensure the data could not be restored without the attacker's cleanup tool. The team behind this was also later linked to some of the original mobile ransomware, which utilized AES encryption. 

### Indicators of Compromise (IoC)
Due to being a locker ransomware rather than modern file-encrypting ransomware, the IoCs focus on persistence, UI suppression, and specific network behaviors, such as: 

#### System Persistence & Registry Keys
- **Winlogon Shell Hijack:** Often, it would change `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` from `explorer.exe` to the malicious executable path (`%AppData%\<random>.exe`).
- **Service DLL Injection:** Some variants would modify `HKLM\SYSTEM\ControlSet001\services\Winmgmt\Parameters\ServiceDll` to point to a malicious DLL in `<commonappdata>` with a reverse filename. 
- **Startup Shortcuts:** Unexpected `.lnk` files in the Startup Menu, such as `explorer.lnk` or `system.lnk`, which pointed to malicious `.cpp` or `.exe` files. 

#### Browser & UI Indicators
- **Security Zone Modification:** Reveton would lower Internet Explorer (IE) security settings by setting `Zones\0-4` value `1609` to `0`.
- **UI Suppression:**
  - It would terminate `explorer.exe` to remove the taskbar and Start Menu.
  - It would automatically terminate `taskmgr.exe` whenever the user tried to launch it. 
- **Fake Security Warnings:** It would also disable "Protected Mode" in IE through the registry setting `NoProtectedModeBanner = 1`. 

#### Network & Host-Based Artifacts
- **IP-Based Geo-Targeting:** The malware would immediately query the system's public IP address to serve a localized police template (e.g., FBI for U.S. IPs, Metropolitan Police for UK IPs).
- **Webcam Activity:** Sudden, unauthorized activation of the system's webcam to display a live feed of the victim on the lockscreen.
- **Exploit Kit Footprints:** Presence of artifacts from the Blackhole Exploit Kit, its primary distribution method, which targeted outdated Java, Flash, and Adobe Reader plugins.

#### File-Based Indicators
- **Location:** Malicious binaries were generally hidden in `%AppData%`, `%Temp%`, or `%CommonAppData%` folders while using randomized alphanumeric names (such as `skype.dat` or `wpbt0.dll`).
- **Audio Files:** In some later variants, the presence of localized `.wav` files used to play an automated voice message demanding payment was also witnessed. 

### Special Features
Reveton was a pioneer in geo-targeting; it would query the public IP address of the victim to tailor the extortion experience to their specific country. Notable aspects of this include:
- **Localized Templates:** It displayed logos and official sounding warnings from the relevant local authority, such as the FBI (USA), Metropolitan Police (UK), or Bundespolizei (Germany).
- **Language Support:** The ransom message was presented in the victim's native language.
- **Regional Payment Methods:** It offered payment options popular in the victim's specific region, such as MoneyPak in the U.S. and Ukash or Paysafecard in Europe. 

Reveton also included the feature to detect and activate the victim's webcam, which resulted in:
- The lockscreen showing a live video feed of the victim. 
- This created a chilling effect that would trick the user into believing they were under active surveillance and being recorded by the police for "illegal" activities. 

Later variants included audio messages, which is notable because: 
- Rather than just reading a warning, the victim would hear an automated voice message that urged them to pay the fine. 
- Much like the text, the audio was also localized, resulting in the victim being spoken to in their native language. 

Reveton did not utilize a simple popup window; instead, it would take over the machine's primary functions, such as:
- **Process Termination:** Reveton was designed to automatically close Task Manager (`taskmgr.exe`) every time a user attempted to launch it to kill the malware. 
- **Desktop Suppression:** `explorer.exe` was either terminated or blocked, leaving the user with no access to their desktop, files, or Start Menu. 
- **System Disruption:** Some variants were even capable of disabling the Windows Firewall to prevent the system from communicating with security updates or receiving remote help. 

### 5. Real-World Incidents
Since Reveton was another ransomware that primarily affected individual users rather than organizations, incidents are typically referred to through waves or law enforcement takedowns. Notable incidents include: 
- **The 2012 FBI Surge:** In August 2012, the Internet Crime Complaint Center (IC3) was inundated with complaints from U.S. users whose computers were locked by the fake FBI warning.
- **The Dubai Arrest (2013):** A 27 year old Russian national, allegedly the mastermind behind the Reveton distribution cell, was arrested in Dubai. His group was estimated to have extorted over $1.3 million per year.
- **The 2014 Pony Evolution:** Researchers discovered a major Reveton variant that had integrated the "Pony Stealer" module, allowing it to steal credentials for 17 different German banks and digital currency wallets like Bitcoin and Dogecoin.
- **Raymond Uadiale Case (2018):** A former Microsoft engineer was sentenced to 18 months in prison for laundering nearly $94,000 in Reveton ransom payments through Liberty Reserve for a UK based co-conspirator.
- **J.P. Morgan Extradition (2024):** Maksim Silnikau (aka "J.P. Morgan"), the alleged creator of Reveton and the Ransomware-as-a-Service model, was extradited from Poland to the U.S. to face charges for a decade long cybercrime spree.

---

## CryptoLocker: 2013
### 1. Overview
CryptoLocker was a major Trojan ransomware that targeted Windows systems through email attachments, as well as the Gameover ZeuS botnet. Although the original version of this malware was dismantled, it served as a primary blueprint for modern ransomware. 

#### Origin and discovery
Identified by the DoJ as the ringleader, Evgeniy Bogachev, also known as "lucky12345" and "slavik," created the original CryptoLocker. This malware was developed by the same criminal organization that created the GameOver ZeuS botnet; which was the infrastructure primarily responsible for the original infections of CryptoLocker. 

#### Target industries
Unlike previous ransomware strains, CryptoLocker was not a "lone wolf" style attack; it was a high-volume, indiscriminate "spray and pray" campaign. Globally, this malware targeted Windows users, focusing mostly on the United States and Great Britain. 

### 2. Attack Methodology
The malware was distributed through the Gameover ZeuS (GOZ) botnet, which was a massive network of infected computers. There was no specific criteria for who was targeted; instead, the group aimed to infect as many users as possible. 

#### Initial access techniques
The primary method of delivering CryptoLocker was through GOZ. Attackers would create emails designed to look like routine business correspondence, such as FedEx or UPS tracking notices and payroll complaints. This would trick office workers and home users into clicking malicious links or downloading malicious attachments. The entire chain for initial access was as follows:
- **The Infrastructure:** At the point of CryptoLocker's creation, the GOZ botnet was already massive. Bogachev's team utilized this foothold as a delivery engine for the malware.
- **The Payload:** Once ready, the botnet began sending out emails with malicious attachments (usually .zip files) disguised as PDFs (such as `invoice.pdf.exe`).
- **The "Double Extension" Trick:** Due to the fact that Windows generally hides known file extensions by default, the file would display as `invoice.pdf` while dropping the `.exe` at the end. Users clicking this would initiate the malware. 
- **Secondary Vector:** There was a lesser known vector through the Cutwail botnet, which operated in the same manner as the GOZ botnet distribution methods. 

#### Lateral movement
CryptoLocker was a fully automated attack orchestrated through the GOZ botnet. There was no lateral movement as part of the attack, as it was purely a volume-based campaign. Consequently, the malware was limited to encrypting only what the logged-in user had permission to modify. 

#### Encryption process
This version of malware utilized a highly professional and multi-layered approach to encryption. This approach combined symmetric and asymmetric encryption and utilized the Microsoft CryptoAPI to ensure the encryption was technically sound and unable to be broken by contemporary security tools. The encryption routine was as follows:
- **Key Pair Generation:** Once a system was infected, the malware would contact its command and control (C2) server; this would generate a unique 2048-bit RSA key pair. 
- **Key Retrieval:** The server would keep the private key and send the public key back to the victim's computer. 
- **File-Level Encryption (AES):** For each matching file (.docx, .pdf, .jpg, etc.), CryptoLocker would create a unique 256-bit AES symmetric key. This key was used to encrypt the contents of the file due to its speed compared to RSA for large amounts of data. 
- **Key Wrapping (RSA):** Once the file was encrypted, the malware would use the RSA public key from the previous step to encrypt the AES key used for that specific file. 
- **Metadata Attachment:** The RSA-encrypted AES key and other metadata were then prepended or appended to the encrypted file data. 
- **Final Write:** The original file was then overwritten with the "wrapped" encrypted package. 

These factors ensured the attack's effectiveness:
- **Unique Keys:** Every single file on the computer had a different AES key, but all of them were locked behind the same RSA public key.
- **Offline Barrier:** Because the RSA private key never left the attacker's server, a victim could not extract a master key from their own computer's memory to undo the damage.
- **Extension Changes:** Depending on the specific sub-version, the malware would append extensions like .encrypted, .cryptolocker, or a string of 7–8 random characters to the filenames.

### 3. Indicators of Compromise (IoC)
#### File System Indicators
- **Malicious Executables:** The primary malware file was generally named randomly (such as `Rlshoaujsjnfs.exe`) or used a GUID (such as `{34285B07-372F-121D-311F-030FAAD0CEF3}.exe`). These were usually located in: 
  - `%AppData%` (Roaming)
  - `%LocalAppData%` 
- **Encrypted File Extensions:** Earlier versions did not change the extension, but later sub-variants began to append: 
  - `.encrypted`
  - `.cryptolocker`
  - A random 7-8 character string (example: `file.docx.ab12cd34`)
- **Ransom Notes:** Directories containing encrypted data would contain a note, typically named: 
  - `DECRYPT_INSTRUCTION.txt`
  - `DECRYPT_INSTRUCTIONS.html`

#### Registry Indicators (Windows)
CryptoLocker utilized the registry as a persistence mechanism and a way of tracking progress: 
- **Persistence Keys:** The malware created an "autorun" entry to ensure it started with the user: 
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with a value named CryptoLocker or a random string.
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` with a value starting with an asterisk (such as `*CryptoLocker`) to bypass Safe Mode.
- **Configuration Keys:** Unique public keys and settings were stored in: 
  - `HKCU\Software\CryptoLocker`
  - `HKCU\Software\CryptoLocker_0388`
- **File Manifest:** A complete manifest of every successfully encrypted file was stored in: 
  - `HKCU\Software\CryptoLocker\Files`

#### Network Indicators
- **DGA (Domain Generation Algorithm):** CryptoLocker would generate 1,000 unique domains per day to find its C2 server. 
  - **Domain Patterns:** 12 to 15 random alphabetical characters (example: `skgiwejixdhjsa.com`).
  - TLDs used: .com, .net, .org, .info, .biz, and .ru. 
- **C2 Communication:** The malware would generally make an initial HTTP POST request to a hardcoded IP or domain (example: `http://<IP_Address>/home/`) to register the infection. 

#### Targeted File Types
A strong indicator of the 2013 variant is the targeting of the following list of extensions while leaving others (like .exe and .dll) untouched: 
- **Office/Productivity:** .doc, .docx, .xls, .xlsx, .ppt, .pptx, .pdf, .rtf, .odt
- **Creative/Professional:** .psd, .ai, .indd, .dwg, .dxf
- **Database/Email:** .mdb, .accdb, .mdf, .dbf, .pst

### 4. Special Features
- **The First "Bulletproof" Encryption:** Prior to CryptoLocker, most ransomware was considered "scareware" due to weak, symmetric-only encryption. CryptoLocker was the first to successfully implement RSA-2048 asymmetric encryption, emphasizing that files could not be recovered without a backup. 
- **The "Tick-Tock" Psychological Warfare:** CryptoLocker included an active countdown timer. The GUI displayed a clock counting down toward the destruction of the private key. 
- **The "Laggard" Penalty (The Decryption Service):** If the 72-hour timer reached zero, the "CryptoLocker Decryption Service" hidden website allowed victims to upload files for a significantly higher price (rising from ~0.5 BTC to 10 BTC). This was an early precursor to modern Ransomware Support Desks. 
- **Bitcoin as the Standard:** CryptoLocker was the first major malware to demand Bitcoin as the primary payment method, granting attackers anonymity and ease of use for global transfers. 
- **Botnet-as-a-Service Distribution:** It utilized an existing botnet (GOZ) rather than spreading itself. This separation of the infection vector from the payload paved the way for modern affiliate programs and initial access brokers (IABs). 

### 5. Real-World Incidents
CryptoLocker infected between 234,000 and 250,000 systems in its first several months. Notable impacts include:
- **Australian Broadcasting Corporation (ABC):** ABC fell victim to a variant that disrupted internal systems. 
- **Small Businesses and Charities:** Reports included a charity worker in London whose computer was encrypted via a phishing email disguised as a bank notification, highlighting how the malware hit non-profits and individuals alike. 
- **Police Departments:** Multiple small-town police departments in the U.S. were reportedly infected and paid the ransom due to a lack of viable backups.
---

---

## Tox RaaS: 2015
### Overview
Tox was a pioneering Ransomware-as-a-Service (RaaS) platform, which significantly lowered the technical barrier for cybercrime by offering "do-it-yourself" ransomware kits for free. 

#### Origin and discovery
Initially discovered on May 19, 2015, by researchers at McAfee Labs, Tox was hosted on the Tor network and utilized a specific .onion address. It appeared as a web-based portal where users could freely register, making it easy for anyone to create a custom ransomware executable in three simple steps: 
- Setting up a ransom amount
- Entering a "cause" for the attack
- Solving a CAPTCHA

In June 2015, shortly after discovery, the original creator called it quits, citing that the platform's unexpected success and the resulting attention were reasons for selling it on the dark web. On top of all this, Tox had no upfront cost; it would split the profits with the attackers and generate a technical payload disguised as a Word document or screensaver. 

#### Target industries
Being a distributed service, there were many different "affiliates," which resulted in the malware not being used against any one single target. Rather, the malware contributed to a large wave of attacks across multiple sectors, such as:
- **General Consumers & Small Businesses:** Early RaaS kits like Tox often targeted random individuals through spam and phishing, as the affiliates were frequently less-skilled "script kiddies."
- **Manufacturing:** This sector was increasingly targeted during 2015, with notable breaches in the clothing and aerospace supply chains.
- **Financial Services:** Though more sophisticated groups targeted this sector, the general rise of RaaS led to increased opportunistic attacks on financial institutions.
- **Healthcare:** Attacks on medical institutions began to gain traction in 2015 due to the critical nature of their data and aging IT infrastructure.

### Attack Methodology
The attack itself was a very simple operation by modern standards, with the primary focus being broad infection rather than deep network penetration. The infection chain looked like this:
- The affiliate downloads the `.scr` payload from the Tox onion site.
- The affiliate sends the payload through a phishing email or their chosen method.
- The victim executes the file.
- Tox encrypts the local disk and any connected devices. 
- Tox displays a ransom note with a Bitcoin address and instructions to pay through the Tor browser. 

#### Initial access techniques
There were a few different methods of initial access, such as:
- **Phishing Variants:** The users, or affiliates, of Tox would generally distribute the malware through mass email campaigns. These emails used classic deception tactics, such as fake invoices, shipping notifications, or critical system updates. 
- **Malicious Attachments:** The Tox platform would create a 2MB `.scr` file (Windows screensaver executable). The reason for this is that it is often overlooked by basic email filters and would allow the file to pass through undetected using a Word or PDF icon to trick the user into clicking it. 
- **No Centralized Infrastructure:** Due to Tox being a "kit," there was no single, unified attack campaign. Each affiliate used their own method of delivery, which ranged from phishing to drive-by-downloads on compromised websites. 

#### Lateral movement
Much like previous ransomware and in contrast to modern variants, Tox did not include any sort of lateral movement. The malware was an all-in-one executable and did not include any sophisticated mechanisms for persistence or movement. 

#### Encryption process
Even though Tox was considered a budget kit for novices, it was noted for its use of established cryptographic libraries. Tox primarily used AES to encrypt the victim's files; the malware was compiled in MinGW and used the Crypto++ library to handle the AES operations. In order to generate the keys, it utilized the Microsoft CryptoAPI and primarily targeted a variety of user-created files, such as:
- `.txt`
- `.doc`
- `.jpg`
- `.png`
- `.pdf`

### Indicators of Compromise (IoC)
There are a number of specific IoCs related to the Tox RaaS platform; these reflect the malware's reliance on external tools, such as `Curl` and Tor. 

#### File-Based Indicators
- **File Extension:** The primary payload was typically an executable disguised with a .scr (Windows screensaver) extension, often using a Microsoft Word icon to deceive users.
- **File Size:** Generated binaries were consistently around 2MB in size.
- **Internal Strings:** The malware contained unique debugging and file path strings from the developer's environment, such as:
  - `C:/Users/Swogo/Desktop/work/tox/cryptopp/secblock.h`
  - `C:/Users/Swogo/Desktop/work/tox/cryptopp/filters.h`
  - `C:/Users/Swogo/Desktop/work/tox/cryptopp/cryptlib.h`
  - `C:/Users/Swogo/Desktop/work/tox/cryptopp/simple.h`

#### Network-Based Indicators
The first actions that the malware takes once activated is to download required communication components from specific URLs, such as:
- **Curl Download:** `hxxp://www.paehl[.]com/open_source/?download=curl_742_1.zip`
- **Tor Client Download:** `hxxp://dist.torproject[.]org/torbrowser/4.5.1/tor-win32-0.2.6.7.zip`

#### Host-Based Activity
- **Data Directory:** Tox would download the Tor client and other essential operational files to the following directory:
  - `C:\Users\<user>\AppData\Roaming\.`
- **Encryption Target List:** The ransomware targeted a broad range of data, specifically looking for extensions including:
  - `.txt`, `.odt`, `.doc`, `.ppt`, `.jpg`, `.png`, `.bmp`
- **Shadow Copies:** Notably, Tox did not delete Volume Shadow Copies, meaning tools like `ShadowExplorer` could often be used for recovery during that era.

### 4. Special Features
What stands out primarily about Tox is less about technical aspects and more about the business model. Tox did not have the aggressive extortion techniques that modern ransomware has now, but it stood out for democratizing cybercrime. Key features included: 
- **The Affiliate Program:** Prior to Tox, ransomware was considered the domain of sophisticated groups who wrote and deployed their own code. With Tox, this shifted from exclusive groups to a "franchise" model, allowing people with no coding knowledge to simply "subscribe."
- **Customizable Ransom Logic:** Unlike prior ransomware strains with hard-coded ransom amounts, Tox allowed the affiliate full control over the "business logic." 
  - This model consisted of dynamic pricing, which allowed the attacker to set the ransom amount in Bitcoin, as well as write their own "reason" or message to the victim.
  - This allowed attackers to target different regions with localized prices. 
- **Built-in Victim Tracking Dashboard:** Tox allowed for real-time analytics through a console for the attacker. 
  - This dashboard showed live stats of how many people opened the file, how many paid, and the total profit. 
  - Ransomware officially transformed from a manual lone-wolf attack into a manageable criminal enterprise, paving the way for low-skill users to track hundreds of infections at once. 
- **Automated Decryption Guarantee:** Tox was a pioneer in automating the trust-building process between the criminal and victim. 
  - Once the Tox server detected a Bitcoin payment to the unique address, it would automatically release the decryption key. 
  - This helped ensure that victims received their files, encouraging future victims to pay because the "brand" was seen as "reliable." 
- **Zero-Footprint Onion Infrastructure:** Previous ransomware strains utilized hard-coded C2 IPs that were easy to block, while Tox was built entirely inside the Tor network. 
  - Through the use of this Infrastructure-as-a-Service (IaaS), the affiliate did not need to set up a server or buy a domain. Everything was hosted, and if a security firm took down one phishing link, the `.onion` address remained hidden.
- **Multi-Layered Packaging:** Because everything the malware relied on was bundled in a 2MB file, it was considered "heavy" for its time. 
  - The malware carried its own Tor client and Curl library, meaning it did not rely on the victim's computer having specific software to communicate with the hackers. 

### 5. Real-World Incidents
Due to the anonymous, distributed nature of Tox and the number of affiliates involved, there are no specific high-profile attacks attributed to one group. Instead, notable incidents were characterized by the massive volume of smaller, opportunistic attacks tracked as a single phenomenon. 
- **The Spray and Pray Campaigns (May-June 2015):** The most notable incident was the explosive number of infections following the platform's public release and its discovery by McAfee Labs on May 19, 2015. 
  - Within weeks, researchers began tracking a surge in the specific `.scr` executable across global telemetry. 
  - These campaigns demonstrated that low-skill attackers were now capable of launching global campaigns with almost no investment. 
- **Manufacturing Sector Targets:** Though many attacks were random, the manufacturing sector was targeted more deliberately during this period. Organizations like Hanesbrands Inc. were among the high-profile victims of ransomware waves in 2015. During this time, RaaS kits were primary tools used to disrupt supply chains by encrypting critical order-processing files. 
- **The Script-Kiddie Wave in Education and Local Government:** Tox was especially popular among script kiddies targeting public institutions with minimal security budgets. 
  - There were numerous small-scale incidents reported in local school districts and municipal offices resulting from employees clicking on phishing emails disguised as invoices or shipping notices. 
  - This marked the first time small businesses realized their data could be held hostage through a free online tool, leading to a significant increase in the adoption of off-site backups. 
- **The Creator's Retirement (June 2015):** Only a month after Tox launched, the creator posted a notice to the dark web portal. 
  - The developer claimed to be overwhelmed by the attention and the volume of infections. They offered to sell the whole platform, including source code and database, for 100 Bitcoins. 
  - This was the first time a major RaaS platform changed hands publicly on the dark web, setting the precedent for how these criminal enterprises are bought, sold, and rebranded, as seen later with more professional operations like GandCrab.
