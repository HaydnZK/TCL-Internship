# The Timeline of Ransomware
## Description 
This research study analyzes the evolution of ransomware from its 1989 origins to modern cybercrime operations. It explores the technical shifts in encryption, the professionalization of Ransomware-as-a-Service (RaaS), and the transition from simple data locking to complex triple-extortion tactics.

### Table of Contents
* [The Aids Trojan (PC Cyborg): 1989](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#the-aids-trojan-pc-cyborg-1989)
* [The Birth of Cryptovirology: 1996](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#the-birth-of-cryptovirology-1996)
* [Gpcode (PGPCoder) and Archievus: 2005 to 2006](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#gpcode-pgpcoder--archievus-2005-2006)
* [Winlock (Trojan.Winlock): 2006 to 2007](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#winlock-trojanwinlock-2006-2007)
* [Reventon: 2010 to 2012](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#reveton-2010-2012)
* [CryptoLocker: 2013](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#cryptolocker-2013)
* [Tox RaaS: 2015](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#tox-raas-2015)
* [The Tactical Explosion (Locky and Petya): 2016](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#the-tactical-explosion-locky--petya-2016)
* [Global Disruption (WannaCry and NotPetya): 2017](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#global-disruption-wannacry--notpetya-2017)
* [GandCrab: 2018](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#gandcrab-2018)
* [Maze: 2019](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#maze-2019)
* [Brain Cipher: 2024](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/README.md#brain-cipher-2024)

---

## The AIDS Trojan (PC Cyborg): 1989
### Overview
The AIDS Trojan was the first documented instance of ransomware and was created by biologist Joseph Popp. 

#### **Origin and discovery**
Joseph Popp created the AIDS Trojan and distributed it via 20,000 infected floppy disks. These were handed out to attendees at the World Health Organization (WHO) AIDS conference in Stockholm and sent through the mail via a subscription service list. The disks were labeled "AIDS Information - Introductory Diskettes." The physical packaging included leaflets warning that the software could have adverse effects on other applications and that users would owe compensation to the PC Cyborg Corporation. It explicitly stated that the microcomputer would stop functioning normally if the terms were not met.

#### **Target industries**
The AIDS Trojan targeted a very specific niche by focusing on the 1989 WHO AIDS Conference. Consequently, the majority of the victims were medical researchers, healthcare professionals, and doctors.

### Attack Methodology
#### **Initial access techniques**
The distribution relied entirely on social engineering and physical media. Because the virus was only spread through floppy disks, Popp relied on the trust of the medical community. Despite the printed warnings regarding the potential impact on their systems, many users still installed the program.

#### **Lateral movement**
As a localized Trojan distributed via physical media, this variant did not possess capabilities for lateral movement or network propagation.

#### **Encryption process**
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

### Relevant Photos
* [AIDS Trojan Floppy Disk](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/01_AIDS_Floppy_Disk.webp)
* [AIDS Trojan Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/02_AIDS_Ransom_Note.webp)

---

## The Birth of Cryptovirology: 1996
### Overview
In 1996, Adam L. Young and Moti Yung established the field of Cryptovirology. They introduced this concept through the release of a seminal paper titled "Cryptovirology: Extortion-Based Security Threats and Countermeasures," which was presented at the 1996 IEEE Symposium on Security and Privacy.

#### **Origin and discovery**
This paper was released nearly a decade after the AIDS Trojan, which had relied on easily breakable symmetric cryptography. The research outlined new discoveries that could both advance security and empower malicious actors in the ransomware scene. This work served as the formal blueprint for the sophisticated and virtually unbreakable ransomware seen in the modern threat landscape.

### Theoretical Foundations
- **Asymmetric Advantage:** By 1996, the advancement of public-key cryptography provided a massive advantage to attackers. The authors demonstrated that by using a public key to encrypt data, only the attacker, who holds the corresponding private key, could undo the damage. This eliminated the possibility of victims or researchers creating simple decryption tools as they had for the AIDS Trojan.
- **Cryptoviral Extortion:** The paper describes a theoretical foundation for modern ransomware. It explores the use of a computer virus that can encrypt a victim's data and demand a ransom in exchange for the decryption key, turning cryptography into a weapon for extortion.
- **Electronic Money:** Although it didn't yet exist in its modern form, the authors predicted that attackers would eventually demand payment through electronic money, such as cryptocurrencies, to maintain anonymity and facilitate global transactions.
- **Kleptography:** Alongside Cryptovirology, Young and Yung introduced the idea of Kleptography. This involves the study of stealing information securely and subliminally through the use of asymmetric backdoors hidden within cryptographic systems and protocols.

### Impact on Evolution
- **Shift from Symmetric to Asymmetric:** This marked the transition from "munging" file names with simple keys to the permanent encryption of file contents.
- **Proactive Defense:** The paper also proposed countermeasures, urging the security community to recognize that encryption could be used as a tool for harm just as easily as it's used for protection.

---

## Gpcode (PGPCoder) & Archievus: 2005-2006
### Overview
**Gpcode (PGPCoder):** This is a trojan that encrypts the files on a victim's computer and demands a ransom in order to release them. Although early versions contained flaws that made them easy to crack, Gpcode was recognized as the first ransomware to use asymmetric encryption in the wild. 

**Archievus:** This was a virus created for Windows operating systems and used as a method of extortion. While much smaller in scale than Gpcode, it was also one of the pioneers of ransomware using asymmetric encryption. Much like Gpcode, Archievus contained flaws that made it easy to mitigate once the vulnerability was discovered.

#### **Origin and discovery**
**Gpcode (PGPCoder):** This malware is often associated with the misuse of Pretty Good Privacy (PGP) technology, which was created by Phil Zimmermann in 1991. There's no official attribution as to who created the virus, though it's believed to be related to Russian cybercriminals. The ransom notes were frequently written in Russian or poorly translated English, and early versions were discovered on Russian underground forums. 

**Archievus:** This appeared shortly after Gpcode in 2006. As with Gpcode, there is no definitive information on the author of the virus. 

#### **Target industries**
**Gpcode (PGPCoder):** While this did not target one specific industry exclusively, Gpcode primarily targeted white collar professionals and business environments. 

**Archievus:** Archievus didn't target specific industries; instead, it focused on targeting home computer users. 

### Attack Methodology
Both malware families utilized different social engineering techniques to infect computers and employed asymmetric encryption to lock data. 

#### **Initial access techniques**
**Gpcode (PGPCoder):** The primary access vector for Gpcode was malicious spear phishing emails. These campaigns frequently targeted business users with social engineering lures such as fake job applications or invoices. 

**Archievus:** Archievus was primarily bundled with spam and freeware. It took advantage of drive by downloads, being one of the first to experiment with malicious websites forcing downloads through the browser. It was often hidden inside free utility software or screensavers downloaded from suspicious websites. 

#### **Lateral movement**
Neither Gpcode nor Archievus included any capabilities for lateral movement. At this time, malware was delivered through lone wolf infections. There was no automation for spreading through a network, as the simple goal was to hit one computer and receive one payment. Complex network wide attacks were not yet a feature of ransomware during this period. 

#### **Encryption process**
While both used asymmetric cryptography and RSA to lock files, the two malwares utilized different methods:

**Gpcode (PGPCoder):** This was a sophisticated program that recognized that RSA is computationally expensive and slow. As a workaround, it used a Hybrid Encryption Scheme achieved in three steps:
- **Symmetric Encryption:** For each file, Gpcode would generate a random symmetric key. It used a simple stream cipher in early versions and AES in later versions to quickly encrypt the actual data of photos and documents. 
- **Asymmetric Encryption:** To hide the symmetric key, Gpcode would take that session key and encrypt it with a stronger RSA public key hardcoded into the malware. 
- **The Ransom Note:** Once complete, Gpcode created a `ReadMe.txt` file in each folder explaining the situation and demanding a ransom. 

**Archievus:** This used a universal lock rather than generating unique keys for every victim. It used one hardcoded key for all infections. It would search for the `My Documents` folder and encrypt every file within it. Because it used a single 30 digit password (`987654321098765432109876543210`), decryption became easy for victims once the key was discovered. 

### Indicators of Compromise (IoC)
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

### Special Features
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

### Real-World Incidents
**Gpcode:** 
* **The RSA Arms Race:** This was a famous cat and mouse game with researchers at Kaspersky. The author would release a version with 64 bit encryption; researchers would crack it, prompting the author to release 128 bit, then 256 bit, and eventually RSA-1024 versions. 
* **The Six Story Distributed Crack:** When the 1024 bit version (`.ak`) was released, it was so technically effective that the security community attempted a massive distributed computing project to crack the key. This was one of the first times a single piece of malware forced global researchers to collaborate on a large scale cryptographic problem. 
* **The $20 Home User Extortion:** Unlike modern ransomware demanding millions, Gpcode targeted home users for small amounts, usually around $20, through E-gold or Liberty Reserve. Most victims paid because the cost was lower than taking the computer to a repair shop. 

**Archievus:** 
* **The Affiliate Purchase Scheme:** Instead of a direct ransom, victims were directed to online pharmacies to buy medication. The attacker earned commissions on these sales, effectively outsourcing the payment processing to legitimate retail websites. 
* **The Universal Password Incident:** Because the attacker used the same password for every victim, a researcher discovered the 30 digit key and published it. This immediately neutralized Archievus infections and taught the security community about the vulnerabilities of hardcoded keys.

### Relevant Photos
* [GPcode Ransom Note Example 1](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/03_GPcode_Ransom_Note(1).webp)
* [GPcode Ransom Note Example 2](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/04_GPcode_Ransom_Note(2).webp)
* [Archievus Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/05_Archievus_Ransom_Note.png)

---

## WinLock (Trojan.Winlock): 2006-2007
### Overview
Appearing around 2007, WinLock was one of the first widespread "locker" variants. Rather than encrypting data, it restricted access to the Windows user interface by displaying pornographic images or fake system warnings.

#### **Origin and discovery**
With ties to Russian cybercriminal groups, this malware was notable because it was one of the pioneers of utilizing "screen lockers" rather than encrypting the victim's files. This marked a move toward more extortionate, financially motivated malware as opposed to earlier, simpler Trojan-based extortions. 

#### **Target industries**
The early versions of this malware primarily targeted individual Windows users, particularly focusing on Russian-speaking markets initially. 

### Attack Methodology
WinLock was distributed via social engineering like previous ransomware; however, unlike those witnessed prior, this focused on restricting access to the desktop rather than encrypting files. 

#### **Initial access techniques**
Though the attackers utilized social engineering to deliver the malware, there were several different methods, such as:
  - **Phishing Emails:** Attackers would use spam emails with malicious attachments or links, usually masquerading as legitimate files, such as:
    - Invoices
    - Job Applications
    - Greeting Cards
  - **Compromised Websites:** Users would be lured to malicious websites, occasionally through drive-by downloads, which would trigger the download of the malware without the user's consent. 
  - **Disguise:** Frequently, WinLock would be trojanized, posing as harmless applications, such as:
    - `Adobe Gamma Loader.exe`
    - `VXGame.exe`

#### **Lateral movement**
At this point in time, ransomware was still in its "lone wolf" phase; much like its predecessors, it would infect a single workstation, collecting one payment and moving on. 

#### **Encryption process (System Locking)**
Once WinLock was installed, it would not immediately encrypt files like previous ransomware. Rather, it would take over the Windows OS screen, which prevented users from accessing the desktop, taskbar, and files. Once locked, the malware would display an often pornographic image to harass the user and demand a ransom. In later variants, the screen would even claim to be from law enforcement or request "Windows Product Activation" keys to make the scam seem legitimate. 

### Indicators of Compromise (IoC)
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

### Special Features
As opposed to today's ransomware, early WinLock variants were much less complex; however, there are a few key features that are relevant to this malware, such as: 
  - **SMS-Based Extortion:** The main feature of WinLock was its payment method. Victims were told to send a premium-rate SMS to a specific shortcode to receive an unlock code. This enabled the attackers to collect small, automated payments without needing a complex banking structure. 
  - **Social Engineering and Scareware:** Many versions of WinLock used psychological pressure rather than encryption, such as:
    - **Pornographic Content:** The ransom note would frequently display a full-screen explicit image to embarrass the user into paying quickly.  
    - **Authority Impersonation:** Early variants would pose as a legitimate software alert, such as Windows Product Activation notices, or claim the system was not registered or legal. 
  - **System Integrity Locks:** Unlike modern ransomware, WinLock focused on locking the user out and preventing system usage through: 
    - Blocking Task Manager, Registry Editor, and Command Prompt to prevent manual removal. 
    - Creating a "top-most" window that would stay above all other elements, essentially blocking the UI. 

### Real-World Incidents
This version of WinLock was characterized by high-volume, indiscriminate distribution rather than targeted attacks. Most of the victims of this ransomware were individual home users, as they were less likely to have robust backups or professional IT support. Notable real-world incidents include:
  - **The $16 Million Gang:** This was one of the more notable incidents involving a Moscow-based gang that operated WinLock. Upon their arrest in 2010, authorities revealed that the gang had extorted $16 million (approximately 500 million rubles) from roughly one million victims. 
  - **Widespread Infection:** It is suggested that hundreds of thousands of computers across Russia and Eastern Europe were infected at the peak of the campaign. This demonstrates how quickly small ransoms ($10 to $20) can accumulate.

### Relevant Photos
* [WinLock Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/06_WinLock_Ransom_Note.webp)

---

## Reveton: 2010-2012
### Overview
Known as "FBI Ransomware" or the "Police Trojan," Reveton popularized the "Law Enforcement" lure. It built off of what WinLock started and would lock the screen with a localized message (claiming to be from the FBI or Metropolitan Police) accusing the user of viewing illegal content. Reveton is widely credited with establishing the Ransomware-as-a-Service (RaaS) business model. 

#### **Origin and discovery**
Created by Maksim Silnikau (Belarus), who operated under the alias "J.P. Morgan," the operation also involved Raymond Uadiale (USA/Nigeria), who was later convicted for laundering over $100,000 in Reveton payments. Reveton was originally discovered in Germany, localized as the "BKA" ransomware, before rapidly spreading across Europe and North America using localized templates for more than 24 countries. This was the first ransomware to infect users through heavily automated means. 

#### **Target industries**
Reveton was another ransomware that did not target specific industries, but rather targeted individual users. This malware relied on a "shotgun" approach, which cast a wide net to infect as many personal computers as possible through automated distribution. 

### Attack Methodology
Much like WinLock, this was another locker variant of ransomware; rather than encrypting the victim's files, it would lock the victim out of the computer and display a banner. Alongside the Reveton ransomware, the creator also utilized the Blackhole exploit kit as the primary delivery vehicle. 

#### **Initial access techniques**
Reveton was mostly distributed through malvertising on adult websites, as well as through the Citadel botnet and the Blackhole exploit kit. 

##### **Blackhole Exploit Kit**
The Blackhole exploit kit was a prominent, commercially sold software toolkit that automated the process of infecting a victim's computer by leveraging security vulnerabilities in outdated software like web browsers and their plugins. Active from around 2010 to 2013, it was a "crime-as-a-service" offered for rent on the dark web, lowering the barrier to entry for cybercriminals.

#### **Lateral movement**
At this point in time, ransomware was still in its "lone wolf" phase; much like its predecessors, it would infect a single workstation, collecting one payment and moving on. 

#### **Encryption process (System Locking)**
Much like WinLock, Reveton did not actually encrypt the user's data; rather, it would lock the user out of the UI and their OS. Once the user was locked out, a full-screen display would appear with a fake "legal notice." Later versions of the malware included some encryption, mostly to ensure the data could not be restored without the attacker's cleanup tool. The team behind this was also later linked to some of the original mobile ransomware, which utilized AES encryption. 

### Indicators of Compromise (IoC)
Due to being a locker ransomware rather than modern file-encrypting ransomware, the IoCs focus on persistence, UI suppression, and specific network behaviors, such as: 

#### **System Persistence & Registry Keys**
- **Winlogon Shell Hijack:** Often, it would change `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` from `explorer.exe` to the malicious executable path (`%AppData%\<random>.exe`).
- **Service DLL Injection:** Some variants would modify `HKLM\SYSTEM\ControlSet001\services\Winmgmt\Parameters\ServiceDll` to point to a malicious DLL in `<commonappdata>` with a reverse filename. 
- **Startup Shortcuts:** Unexpected `.lnk` files in the Startup Menu, such as `explorer.lnk` or `system.lnk`, which pointed to malicious `.cpp` or `.exe` files. 

#### **Browser & UI Indicators**
- **Security Zone Modification:** Reveton would lower Internet Explorer (IE) security settings by setting `Zones\0-4` value `1609` to `0`.
- **UI Suppression:**
  - It would terminate `explorer.exe` to remove the taskbar and Start Menu.
  - It would automatically terminate `taskmgr.exe` whenever the user tried to launch it. 
- **Fake Security Warnings:** It would also disable "Protected Mode" in IE through the registry setting `NoProtectedModeBanner = 1`. 

#### **Network & Host-Based Artifacts**
- **IP-Based Geo-Targeting:** The malware would immediately query the system's public IP address to serve a localized police template (such as FBI for U.S. IPs, Metropolitan Police for UK IPs).
- **Webcam Activity:** Sudden, unauthorized activation of the system's webcam to display a live feed of the victim on the lockscreen.
- **Exploit Kit Footprints:** Presence of artifacts from the Blackhole Exploit Kit, its primary distribution method, which targeted outdated Java, Flash, and Adobe Reader plugins.

#### **File-Based Indicators**
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

### Real-World Incidents
Since Reveton was another ransomware that primarily affected individual users rather than organizations, incidents are typically referred to through waves or law enforcement takedowns. Notable incidents include: 
- **The 2012 FBI Surge:** In August 2012, the Internet Crime Complaint Center (IC3) was inundated with complaints from U.S. users whose computers were locked by the fake FBI warning.
- **The Dubai Arrest (2013):** A 27 year old Russian national, allegedly the mastermind behind the Reveton distribution cell, was arrested in Dubai. His group was estimated to have extorted over $1.3 million per year.
- **The 2014 Pony Evolution:** Researchers discovered a major Reveton variant that had integrated the "Pony Stealer" module, allowing it to steal credentials for 17 different German banks and digital currency wallets like Bitcoin and Dogecoin.
- **Raymond Uadiale Case (2018):** A former Microsoft engineer was sentenced to 18 months in prison for laundering nearly $94,000 in Reveton ransom payments through Liberty Reserve for a UK based co-conspirator.
- **J.P. Morgan Extradition (2024):** Maksim Silnikau (aka "J.P. Morgan"), the alleged creator of Reveton and the Ransomware-as-a-Service model, was extradited from Poland to the U.S. to face charges for a decade long cybercrime spree.

### Relevant Photos
* [Reveton Law Enforcement Theme Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/07_reveton_Ransom_Note.png)

---

## CryptoLocker: 2013
### Overview
CryptoLocker was a major Trojan ransomware that targeted Windows systems through email attachments, as well as the Gameover ZeuS botnet. Although the original version of this malware was dismantled, it served as a primary blueprint for modern ransomware. 

#### **Origin and discovery**
Identified by the DoJ as the ringleader, Evgeniy Bogachev, also known as "lucky12345" and "slavik," created the original CryptoLocker. This malware was developed by the same criminal organization that created the GameOver ZeuS botnet; which was the infrastructure primarily responsible for the original infections of CryptoLocker. 

#### **Target industries**
Unlike previous ransomware strains, CryptoLocker was not a "lone wolf" style attack; it was a high-volume, indiscriminate "spray and pray" campaign. Globally, this malware targeted Windows users, focusing mostly on the United States and Great Britain. 

### Attack Methodology
The malware was distributed through the Gameover ZeuS (GOZ) botnet, which was a massive network of infected computers. There was no specific criteria for who was targeted; instead, the group aimed to infect as many users as possible. 

#### **Initial access techniques**
The primary method of delivering CryptoLocker was through GOZ. Attackers would create emails designed to look like routine business correspondence, such as FedEx or UPS tracking notices and payroll complaints. This would trick office workers and home users into clicking malicious links or downloading malicious attachments. The entire chain for initial access was as follows:
- **The Infrastructure:** At the point of CryptoLocker's creation, the GOZ botnet was already massive. Bogachev's team utilized this foothold as a delivery engine for the malware.
- **The Payload:** Once ready, the botnet began sending out emails with malicious attachments (usually .zip files) disguised as PDFs (such as `invoice.pdf.exe`).
- **The "Double Extension" Trick:** Due to the fact that Windows generally hides known file extensions by default, the file would display as `invoice.pdf` while dropping the `.exe` at the end. Users clicking this would initiate the malware. 
- **Secondary Vector:** There was a lesser known vector through the Cutwail botnet, which operated in the same manner as the GOZ botnet distribution methods. 

#### **Lateral movement**
CryptoLocker was a fully automated attack orchestrated through the GOZ botnet. There was no lateral movement as part of the attack, as it was purely a volume-based campaign. Consequently, the malware was limited to encrypting only what the logged-in user had permission to modify. 

#### **Encryption process**
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

### Indicators of Compromise (IoC)
#### **File System Indicators**
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

#### **Registry Indicators (Windows)**
CryptoLocker utilized the registry as a persistence mechanism and a way of tracking progress: 
- **Persistence Keys:** The malware created an "autorun" entry to ensure it started with the user: 
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with a value named CryptoLocker or a random string.
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` with a value starting with an asterisk (such as `*CryptoLocker`) to bypass Safe Mode.
- **Configuration Keys:** Unique public keys and settings were stored in: 
  - `HKCU\Software\CryptoLocker`
  - `HKCU\Software\CryptoLocker_0388`
- **File Manifest:** A complete manifest of every successfully encrypted file was stored in: 
  - `HKCU\Software\CryptoLocker\Files`

#### **Network Indicators**
- **DGA (Domain Generation Algorithm):** CryptoLocker would generate 1,000 unique domains per day to find its C2 server. 
  - **Domain Patterns:** 12 to 15 random alphabetical characters (example: `skgiwejixdhjsa.com`).
  - TLDs used: .com, .net, .org, .info, .biz, and .ru. 
- **C2 Communication:** The malware would generally make an initial HTTP POST request to a hardcoded IP or domain (example: `http://<IP_Address>/home/`) to register the infection. 

#### **Targeted File Types**
A strong indicator of the 2013 variant is the targeting of the following list of extensions while leaving others (like .exe and .dll) untouched: 
- **Office/Productivity:** .doc, .docx, .xls, .xlsx, .ppt, .pptx, .pdf, .rtf, .odt
- **Creative/Professional:** .psd, .ai, .indd, .dwg, .dxf
- **Database/Email:** .mdb, .accdb, .mdf, .dbf, .pst

### Special Features
- **The First "Bulletproof" Encryption:** Prior to CryptoLocker, most ransomware was considered "scareware" due to weak, symmetric-only encryption. CryptoLocker was the first to successfully implement RSA-2048 asymmetric encryption, emphasizing that files could not be recovered without a backup. 
- **The "Tick-Tock" Psychological Warfare:** CryptoLocker included an active countdown timer. The GUI displayed a clock counting down toward the destruction of the private key. 
- **The "Laggard" Penalty (The Decryption Service):** If the 72-hour timer reached zero, the "CryptoLocker Decryption Service" hidden website allowed victims to upload files for a significantly higher price (rising from ~0.5 BTC to 10 BTC). This was an early precursor to modern Ransomware Support Desks. 
- **Bitcoin as the Standard:** CryptoLocker was the first major malware to demand Bitcoin as the primary payment method, granting attackers anonymity and ease of use for global transfers. 
- **Botnet-as-a-Service Distribution:** It utilized an existing botnet (GOZ) rather than spreading itself. This separation of the infection vector from the payload paved the way for modern affiliate programs and initial access brokers (IABs). 

### Real-World Incidents
CryptoLocker infected between 234,000 and 250,000 systems in its first several months. Notable impacts include:
- **Australian Broadcasting Corporation (ABC):** ABC fell victim to a variant that disrupted internal systems. 
- **Small Businesses and Charities:** Reports included a charity worker in London whose computer was encrypted via a phishing email disguised as a bank notification, highlighting how the malware hit non-profits and individuals alike. 
- **Police Departments:** Multiple small-town police departments in the U.S. were reportedly infected and paid the ransom due to a lack of viable backups.

### Relevant Photos
* [CryptoLocker Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/08_CryptoLocker_Ransom_Note.webp)

---

## Tox RaaS: 2015
### Overview
Tox was a pioneering Ransomware-as-a-Service (RaaS) platform, which significantly lowered the technical barrier for cybercrime by offering "do-it-yourself" ransomware kits for free. 

#### **Origin and discovery**
Initially discovered on May 19, 2015, by researchers at McAfee Labs, Tox was hosted on the Tor network and utilized a specific .onion address. It appeared as a web-based portal where users could freely register, making it easy for anyone to create a custom ransomware executable in three simple steps: 
- Setting up a ransom amount
- Entering a "cause" for the attack
- Solving a CAPTCHA

In June 2015, shortly after discovery, the original creator called it quits, citing that the platform's unexpected success and the resulting attention were reasons for selling it on the dark web. On top of all this, Tox had no upfront cost; it would split the profits with the attackers and generate a technical payload disguised as a Word document or screensaver. 

#### **Target industries**
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

#### **Initial access techniques**
There were a few different methods of initial access, such as:
- **Phishing Variants:** The users, or affiliates, of Tox would generally distribute the malware through mass email campaigns. These emails used classic deception tactics, such as fake invoices, shipping notifications, or critical system updates. 
- **Malicious Attachments:** The Tox platform would create a 2MB `.scr` file (Windows screensaver executable). The reason for this is that it is often overlooked by basic email filters and would allow the file to pass through undetected using a Word or PDF icon to trick the user into clicking it. 
- **No Centralized Infrastructure:** Due to Tox being a "kit," there was no single, unified attack campaign. Each affiliate used their own method of delivery, which ranged from phishing to drive-by-downloads on compromised websites. 

#### **Lateral movement**
Much like previous ransomware and in contrast to modern variants, Tox did not include any sort of lateral movement. The malware was an all-in-one executable and did not include any sophisticated mechanisms for persistence or movement. 

#### **Encryption process**
Even though Tox was considered a budget kit for novices, it was noted for its use of established cryptographic libraries. Tox primarily used AES to encrypt the victim's files; the malware was compiled in MinGW and used the Crypto++ library to handle the AES operations. In order to generate the keys, it utilized the Microsoft CryptoAPI and primarily targeted a variety of user-created files, such as:
- `.txt`
- `.doc`
- `.jpg`
- `.png`
- `.pdf`

### Indicators of Compromise (IoC)
There are a number of specific IoCs related to the Tox RaaS platform; these reflect the malware's reliance on external tools, such as `Curl` and Tor. 

#### **File-Based Indicators**
- **File Extension:** The primary payload was typically an executable disguised with a .scr (Windows screensaver) extension, often using a Microsoft Word icon to deceive users.
- **File Size:** Generated binaries were consistently around 2MB in size.
- **Internal Strings:** The malware contained unique debugging and file path strings from the developer's environment, such as:
  - `C:/Users/Swogo/Desktop/work/tox/cryptopp/secblock.h`
  - `C:/Users/Swogo/Desktop/work/tox/cryptopp/filters.h`
  - `C:/Users/Swogo/Desktop/work/tox/cryptopp/cryptlib.h`
  - `C:/Users/Swogo/Desktop/work/tox/cryptopp/simple.h`

#### **Network-Based Indicators**
The first actions that the malware takes once activated is to download required communication components from specific URLs, such as:
- **Curl Download:** `hxxp://www.paehl[.]com/open_source/?download=curl_742_1.zip`
- **Tor Client Download:** `hxxp://dist.torproject[.]org/torbrowser/4.5.1/tor-win32-0.2.6.7.zip`

#### **Host-Based Activity**
- **Data Directory:** Tox would download the Tor client and other essential operational files to the following directory:
  - `C:\Users\<user>\AppData\Roaming\.`
- **Encryption Target List:** The ransomware targeted a broad range of data, specifically looking for extensions including:
  - `.txt`, `.odt`, `.doc`, `.ppt`, `.jpg`, `.png`, `.bmp`
- **Shadow Copies:** Notably, Tox did not delete Volume Shadow Copies, meaning tools like `ShadowExplorer` could often be used for recovery during that era.

### Special Features
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

### Real-World Incidents
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

### Relevant Photos
* [TOX Ransomware Builder GUI](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/09_TOX_Ransomware_GUI.png)
* [TOX Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/10_TOX_Ransom_Note.webp)
* [TOX Decryption Instructions](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/11_TOX_How_To.jpg)

---

## The Tactical Explosion (Locky & Petya): 2016
### 1. Overview
**Locky:** Locky was a ransomware released in 2016 that was frequently delivered through phishing emails, generally pretending to be an invoice, that took advantage of Windows macros. Once active, the ransomware instructs the victim to download the Tor browser and visit a specific criminal-operated website for more information. 

**Petya:** Petya was another malware discovered in 2016 that targets Windows-based systems, specifically the Master Boot Record (MBR) in order to execute a payload. Much like most malware, Petya was primarily delivered through phishing emails and was used in a global attack, although it particularly focused on Ukraine. 

#### Origin and discovery
**Locky:** Discovered in February 2016, Locky was created by the Necurs group. It was used in large phishing campaigns that delivered the file through Microsoft Word documents containing malicious macros. 

**Petya:** Petya originally surfaced in March 2016 as a cybercriminal Ransomware-as-a-Service created by a group known as the Janus Syndicate. Its more famous 2017 variant, NotPetya, has been formally attributed by the U.S. and U.K. governments to the Russian military (GRU) as a state-sponsored attack intended to destabilize Ukraine.

#### Target industries
**Locky:** Locky ransomware was distributed through massive, indiscriminate spam campaigns that could affect any user, though it prioritized industries with time-sensitive records and high operational urgency. The primary targets included:
- **Healthcare:** Attackers targeted hospitals as "low-hanging fruit" due to outdated legacy systems and the critical urgency of patient data. One of the most famous cases involved the Hollywood Presbyterian Medical Center, which paid a $17,000 ransom in February 2016.
- **Manufacturing:** Targeted because production halts create immense financial leverage for attackers.
- **Financial Services:** Banks and insurance companies were hit for their high-value identity data and sensitive financial records.
- **Government & Public Sector:** Agencies were frequently hit due to their reliance on outdated infrastructure and the critical nature of public services.
- **Telecommunications:** Large-scale campaigns often caught employees in this sector through malicious invoices or service reports.
- **Education:** Schools and universities were targeted for their vast stores of personal data and often under-resourced IT departments.
- **Transportation & Logistics:** Disruption in these sectors is costly, making them attractive for extortion.

**Petya:** Petya was primarily focused on Ukraine, though it eventually spread further. This was not targeted at any one industry; however, it hit a number of critical sectors and infrastructure, such as:
- **Finance:** The National Bank of Ukraine.
- **Energy:** Power grids and the radiation monitoring systems at Chernobyl.
- **Logistics:** Major companies like FedEx, TNT, and Maersk.
- **Public Services:** Airports, gas stations, and various government institutions.

### Attack Methodology
**Locky:** Locky utilized a multi-stage attack methodology defined by a high-volume distribution as well as sophisticated evasion techniques. The attack typically followed these steps:
1. **Initial delivery & Social Engineering**
  - **Vector:** The primary delivery method was massive email spam campaigns (malspam), often distributed via the Necurs botnet.
  - **Deception:** Emails were disguised as legitimate business documents like invoices, payment notifications, or delivery receipts.
  - **Payload:** They contained a malicious attachment, most commonly a Microsoft Word or Excel file (sometimes within a ZIP or PDF archive).
2. **Execution Trigger**
  - **Macro Activation:** When opened, the document displays garbled text. A prompt instructs the user to "Enable macros" to view the content correctly.
  - **Malicious Scripting:** Enabling macros triggers an embedded script (often VBA or VBScript) that runs in the background.
3. **Payload Download & Installation**
  - **Downloader:** The script connects to a remote Command and Control (C2) server to download the actual Locky executable (Trojan).
  - **Location:** The executable is typically saved in the %TEMP% directory and renamed to appear as a system file like svchost.exe.
  - **Persistence:** It adds itself to the Windows Registry "Run" key to ensure it restarts if the system is rebooted before encryption finishes.
4. **C2 Communication & Key Exchange**
  - **DGA:** Locky uses a Domain Generation Algorithm (DGA) to generate new C2 domain names daily, making it harder for security tools to block its traffic.
  - **Key Request:** The malware contacts the C2 server to report the infection and request a unique RSA-2048 public key. Encryption only begins after this key is received and stored in the registry.
5. **File Encryption & Recovery Disruption**
  - **Hybrid Encryption:** Locky uses a combination of AES-128 (to encrypt file data) and RSA-2048 (to encrypt the AES keys).
  - **Targeted Files:** It scans all local drives, removable media, and unmapped network shares for over 160 file types, including documents, databases, and images.
  - **Anti-Recovery:** It executes a command (vssadmin.exe Delete Shadows /All /Quiet) to delete Volume Shadow Copies, preventing users from using Windows System Restore to recover files.
6. **Ransom Demand**
  - **Notification:** Once encryption is complete, it changes the desktop wallpaper to a ransom note (often a `.bmp` or `.txt` file).
  - **Instructions:** The note directs the victim to a Tor-based website to pay a ransom in Bitcoin (historically 0.5 to 1 BTC) in exchange for the decryption key.

**Petya:** The original version of Petya lacked the ability to spread on its own, so it relied solely on tricking single users into running it. The attack methodology played out like this:
1. **Initial Infection Vector**
  - **Social Engineering (Phishing):** The primary method was emails targeting HR departments. These emails contained a link to a Dropbox folder supposedly containing a job applicant's resume and photo.
  - **User Execution:** The victim had to manually click the link, download a ZIP file, and execute the .exe file inside (which used a fake folder icon to look harmless).
2. **Privilege Escalation**
  - **UAC Prompt:** Unlike later versions that used exploits, the original Petya simply asked for permission. When run, it triggered a standard Windows User Account Control (UAC) prompt.
  - **The Hook:** If the user clicked "Yes," the malware gained the administrative rights necessary to access the low-level drive functions. If the user clicked "No," the attack failed (though later variants would drop a secondary payload called Mischa instead).
3. **Payload Execution (Phase 1: The MBR Overwrite)**
  - **Master Boot Record (MBR) Hijack:** Once it had admin rights, Petya immediately overwrote the first 512 bytes of the hard drive (the MBR) with its own malicious bootloader code.
  - **Forced Crash:** It then used the `NtRaiseHardError` API to intentionally crash the computer or forced a hardware reboot to seize control of the boot process.
4. **Payload Execution (Phase 2: The Encryption)**
  - **Fake CHKDSK Screen:** Upon rebooting, instead of Windows loading, Petya’s malicious bootloader ran. It displayed a fake screen claiming the file system was being repaired ("Repairing file system on C:").
  - **Master File Table (MFT) Encryption:** While the user waited for the "repair," Petya was actually using the Salsa20 algorithm to encrypt the Master File Table (MFT); the "map" that tells the computer where every file is located. This effectively made the entire drive unreadable.
5. **The Lockout**
  - **Ransom Note:** Once encryption was finished, it displayed a red screen with a flashing skull made of ASCII characters and instructions on how to pay a Bitcoin ransom via a Tor website to get the decryption key.

#### **Lateral movement**
**Locky:** Locky ransomware did not typically engage in sophisticated lateral movement like modern human-operated ransomware groups. Instead, it focused on rapid automated encryption of any accessible resource once it gained a foothold on a single machine.

**Petya:** The original version of Petya did not include any lateral movement as a feature. However, it did become a defining feature of the NotPetya variant of this ransomware. 

#### **Encryption process**
**Locky:** Locky utilized a hybrid encryption scheme combining the speed of symmetric encryption and the security of asymmetric encryption. This is intended to be unbreakable due to the decryption keys being generated and stored on the attacker's server. Here are the steps for the encryption process: 
1. **C2 Check-in:** After infecting a machine, Locky contacts a Command and Control (C2) server. It will not begin encrypting files until it successfully receives a unique RSA-2048 public key from the server. 
2. **Symmetric File Encryption:** Locky scans the system and network shares for specific file types (over 160 extensions). For each file: 
  - It generates a unique, random AES-128 key.
  - The file's content is encrypted using this AES key (typically in CTR or CBC mode in most documented variants; earlier reports occasionally cited ECB).
3. **Asymmetric Key Wrapping:** To ensure the victim cannot access the AES key, Locky uses the RSA-2048 public key (obtained in step 1) to encrypt the AES key. 
4. **Metadata Storage:** The encrypted AES key is then embedded directly into the footer or header of the encrypted file. 
5. **File Renaming:** The original file is renamed to a unique 16-character hexadecimal string and appended with a variant-specific extension (such as `.locky`, `.zepto`, `.osiris`).

**Petya:** The encryption process for Petya happened in two distinct stages, both targeting different parts of the hard drive using separate cryptographic methods. 
1. **Preparation and MBR Overwrite (XOR Encryption)**
Before the system rebooted, the Petya dropper performed low-level disk modifications using simple XOR encryption with the fixed byte 0x37 (ASCII '7'). 
  - **Original MBR Backup:** Petya read the original Master Boot Record (MBR), encrypted its contents with 0x37, and saved this backup to the 56th sector of the disk. 
  - **Malicious Bootloader:** It then overwrote the original MBR at sector 0 with its own malicious code and wrote additional bootstrap data to sectors 34–50. 
  - **Key Storage:** A "configuration sector" (sector 54) was created to store a randomly generated 32-byte encryption key and an 8-byte initialization vector (IV) for the next stage. 
  - **Forced Crash:** The dropper finally triggered a Blue Screen of Death (BSOD) or a forced reboot to execute its new bootloader. 
2. **MFT Encryption (Salsa20 Cipher)**
After the reboot, Petya's malicious bootloader took control before Windows could load. It displayed a fake "repairing file system" (CHKDSK) screen to mask the actual encryption process. 
  - **Targeting the MFT:** Instead of individual files, Petya encrypted the Master File Table (MFT) of the NTFS partition. The MFT serves as the "index" for the entire drive; by locking it, the operating system can no longer locate any files, rendering the disk useless. 
  - **Encryption Algorithm:** It used the Salsa20 stream cipher to encrypt the MFT records. 
  - **Implementation Flaws:** Research by groups like Check Point found that the developers incorrectly implemented Salsa20 by using 16-bit variables (specifically in the `rotl` function) instead of 32-bit ones. This mistake made the key-stream predictable and allowed researchers to create early decryption tools to recover data without paying the ransom.

### Indicators of Compromise (IoC)
**Locky:** Identifying Locky before infection takes hold and the ransom screen shows requires monitoring for specific technical artifacts and behavioral patterns. There are several unique IoCs for this family:
1. **Registry Keys and Configuration:** Locky creates specific registry entries to store its configuration and maintain persistence:
- **Primary Configuration Key:** A key is created at `HKEY_CURRENT_USER\Software\Locky` (or sometimes `HKEY_CURRENT_USER\Locky`), which usually stores: 
  - **id:** A 16-character hexadecimal victim ID.
  - **pubkey:** The RSA-2048 public key received from the C2 server.
  - **paytext:** The text for the ransom note.
  - **completed:** A value set to `1` once encryption is finished. 
- **Persistence:** A value is added to `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` to ensure it resumes if the system restarts during encryption. 
2. **File System Artifacts**
  - **Self-Replication in Temp:** Once executed, Locky will copy itself to the `%TEMP%` directory using a random name (`<random>.exe`) or mimicking a legitimate service, such as `svchost.exe`.
  - **Ransom Note Files:** Instruction files are dropped within every folder that contains encrypted data. Some common names include `_Locky_recover_instructions.txt` and `_Locky_recover_instructions.bmp`.
  - **Encrypted File Naming:** Patterns like `<user_id><random_hash>.locky`; this can contain other variants like `.zepto`, `.osiris`, or `.lukitus`. 
3. **Network Communication & DGA:** Locky is famous for its DGA (Domain Generation Algorithm), helping it to evade static domain blocking:
  - **DGA Behavior:** It creates multiple unique domains each day based on the system date and a hard-coded seed. It attempts to contact these domains sequentially until it finds an active C2 server. 
  - **TLD (Top Level Domains) Patterns:** Earlier variants favor TLDs like `.ru`, `.de`, `.pw`, and `.yt`.
  - **Inbound/Outbound Traffic:** Custom encrypted communication protocols are used to communicate with the C2 server, usually sending parameters such as `&act=getkey` or `&act=report`. 
4. **Process Behavior (Indicators of Attack)**
  - **Shadow Copy Deletion:** A major indicator is the execution of the command `vssadmin.exe Delete Shadows /All /Quiet`. This is an immediate red flag for ransomware activity. 
  - **Anti-Sandbox Checks:** Some variants include a check for the Russian language; if detected, the malware terminates without encrypting. 
  - **RDTSC (Read Time-Stamp Counter) Function Call:** Before domains are created, it may call the RDTSC function as part of its DGA (Domain Generation Algorithm) or to detect if it is being run in a debugger/sandbox. 

**Petya:** The original version of Petya left specific technical signatures on the disk and within the OS that distinguish it from standard ransomware. These indicators include: 
1. **Disk-Level Indicators (Low-Level):** Due to the fact that Petya functions below the OS, the most unique indicators are found in specific hard drive sectors, like:
- **XOR 0x37 Pattern:** Petya backs up the original Master Boot Record (MBR) and other sectors by XORing their content with the byte `0x37` (ASCII '7').
- **Sector 54 (The "Onion" Sector):** Petya creates a configuration block here containing the victim's unique ID, the Salsa20 encryption key, and the Tor payment URL.
- **Sector 55:** This sector is often filled entirely with the repeating filler byte `0x37` as a verification marker. 
- **Sector 56:** This is the specific location where the original, XOR-encrypted MBR is stored.
- **Malicious Kernel (Sectors 34-50):** The malware writes its 16-bit bootloader and malicious kernel to these specific sectors.
2. **System & API Indicators:** Before rebooting, Petya displays some unique behaviors, such as: 
- **NtRaiseHardError Call:** To force the "Blue Screen of Death" (BSOD) that triggers the reboot, Petya uses the undocumented Windows API `NtRaiseHardError`.
- **DeviceIOControl Activity:** The dropper uses the `IOCTL_DISK_GET_PARTITION_INFO_EX` control code to directly identify and access the physical drive, such as `\\.\PhysicalDrive0`, for overwriting.
- **Process Flag Check:** Petya frequently checks for the presence of specific security software processes (such as `AVP.exe` for Kaspersky) before deciding whether to perform a full MFT encryption or simply trash the first sectors of the disk. 
3. **Delivery & Execution Signatures**
- **Fake Folder Icon:** The initial executable (dropper) often used a custom folder icon to trick users into thinking they were opening a directory rather than an application.
- **Dropbox-Hosted Links:** Early 2016 campaigns almost exclusively utilized malicious Dropbox links in phishing emails sent to HR departments.

### Special Features
**Locky:** Locky was one of the pioneers of Ransomware-as-a-Service, but it also acts much differently than modern-day ransomware. Rather than the targeted, multi-layered extortion we have today, it relied on its massive scale. Here are some of the unique features of Locky:
- **Affiliate Programs (The "RaaS" Model)**
  - Locky was one of the first major strains to successfully implement an Affiliate Program. The developers (widely linked to the Dridex group/Evil Corp) maintained the code and infrastructure, while "affiliates" handled the distribution. The developers took a cut of every ransom paid, leveraging their existing botnet infrastructure.
- **Massive "Malspam" Distribution (Necurs Botnet)**
  - While not a "worm" that spreads via vulnerabilities (like WannaCry), Locky had a unique distribution engine. It partnered with the Necurs botnet, which at the time was the world’s largest spam engine. This allowed Locky to achieve "worm-like" impact through sheer volume, hitting millions of inboxes simultaneously.
- **Advanced DGA (Domain Generation Algorithm)**
  - To prevent defenders from blocking its communication, Locky used a sophisticated DGA. It would generate a massive list of potential "phone home" domains every day. If a security company took down one domain, the malware would move to the next one on its mathematically generated list.
- **Language-Based "Kill Switch"**
  - Locky featured a geographic safeguard: it would check the system’s default language and keyboard layout. If it detected Russian or several other Cyrillic languages (CIS countries), it would self-terminate and uninstall without encrypting anything. This helped the developers avoid local law enforcement scrutiny.
- **Offline Encryption Capability**
  - While it preferred to get a key from a server, some variants had a "fail-safe" where they could encrypt files using a hardcoded public key if the C2 server was unreachable. This ensured the attack would succeed even if the victim’s internet was cut or the attackers' servers were down.

**Petya:** While not as flashy as modern day ransomware, Petya did have some unique characteristics that helped define it, such as:
- **Ransomware-as-a-Service (RaaS)/Affiliate Program**
  - The original Petya was one of the first major examples of the Affiliate Model. The creators (Janus Syndicate) didn't just spread the virus themselves; they hosted a portal where other hackers could sign up, download the malware, and keep a percentage of the ransom (ranging from 25% up to 85% depending on the volume of infections).
- **Low-Level Disk Hijacking**
  - Most ransomware encrypts files while Windows is running. Petya’s "special feature" was that it exited the OS entirely. By overwriting the Master Boot Record (MBR), it forced the computer to boot into its own custom, malicious "mini-operating system" to perform the encryption.
- **MFT Encryption (The "Index" Attack)**
  - Instead of wasting time encrypting every single photo or document, Petya only targeted the Master File Table (MFT). This is the "table of contents" for the hard drive. By locking just this one file, it made the entire drive appear empty and unreadable in seconds.
- **Social Engineering Focus (The HR Ruse)**
  - The original campaign was highly specific. It used a targeted phishing strategy involving fake job applications. It used custom folder icons to trick users into thinking they were opening a resume folder on Dropbox rather than an executable file.
- **The "Red Skull" Branding**
  - While many ransomware notes were just text files, Petya featured a dramatic, flashing red ASCII skull on the boot screen. This high-production branding was designed to intimidate victims into paying quickly.

### Real-World Incidents
**Locky:** Locky primarily focused on automated, wide-spread spam campaigns rather than specific targets, though it did cause several high-profile disruptions in 2016 and 2017; particularly in the healthcare and education sectors. 
1. **Healthcare: The Low-Hanging Fruit:** Locky brought ransomware into the world spotlight when it began impacting hospitals and risking the safety of patients. 
- **Hollywood Presbyterian Medical Center (February 2016):** This remains the most famous Locky incident. The hospital was forced into an "internal state of emergency" for over a week after Locky encrypted its network via a malicious email attachment.
  - **Impact:** Staff had to use paper records and fax machines; some patients were diverted to other facilities.
  - **Outcome:** The hospital paid a $17,000 ransom (40 Bitcoins at the time) to regain access, determining it was the "quickest and most efficient" way to restore care.
- **Methodist Hospital, Henderson, Kentucky (March 2016):** The hospital declared an internal state of emergency after a staff member opened a booby-trapped invoice email.
  - **Impact:** To stop the spread, the hospital shut down its entire network and checked every device individually.
  - **Outcome:** Unlike Hollywood Presbyterian, they reportedly refused to pay the $1,600 ransom and successfully restored data from backups.
- **Other Healthcare Targets:** In 2016 alone, several other facilities were hit, including Chino Valley Medical Center, Desert Valley Hospital, and The Ottawa Hospital. While Ottawa recovered by wiping drives and using backups, others suffered significant downtime.

2. **Government and Education**
- **Cockrell Hill Police Department, Texas (December 2016):** This department was hit by the Osiris variant of Locky.
  - **Impact:** The malware encrypted years of critical data, including body camera footage, in-car video, and surveillance photos dating back to 2009.
  - **Outcome:** They lost access to a significant portion of this evidence because they lacked comprehensive backups and refused to pay the $4,000 ransom.
- **UK Schools (Spring 2016):** Dartford Grammar School and Dartford Science & Technology College were infected after a student opened a malicious email.
  - **Impact:** The virus encrypted many school files and persisted for weeks.
  - **Outcome:** IT staff eventually removed the virus and restored files using Windows System Restore.

3. **Global Prevalence**
At its peak, Locky was sent to roughly half a million users each day, eventually increasing into the millions. The automated nature meant that the majority of smaller victims across Germany, France, India, and the US were hit. It is worth noting that it avoided Russia and CIS countries due to the built-in language check. 

**Petya:** The original version of Petya was much smaller than its counterpart, NotPetya, resulting in much less global disruption. Petya was primarily used for targeted criminal extortion; a couple of notable cases include:
- **German HR Departments:** The primary known incidents involved localized phishing campaigns targeting Human Resources departments in Germany, where the malware was disguised as job applications.
- **Conviction in Ukraine:** In August 2018, a Ukrainian citizen was sentenced to one year in prison for spreading a version of the original Petya online.

### Relevant Photos
* [Locky Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/12_Locky_Ransom_Note.png)
* [Petya Boot Screen Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/13_Petya_Ransom_Note.webp)

---

## Global Disruption (WannaCry & NotPetya): 2017
### 1. Overview
**NotPetya:** NotPetya is a destructive "wiper" malware disguised as ransomware that launched a massive global cyberattack in June 2017. While it mimicked the original Petya’s appearance, its true purpose was to permanently destroy data rather than collect ransom, primarily targeting Ukraine’s critical infrastructure before spreading worldwide.

**WannaCry:** WannaCry is a 2017 global cryptoworm that infected over 300,000 computers by exploiting the EternalBlue vulnerability in Windows' SMB protocol. Unlike Locky, it spread automatically across networks without user interaction, famously crippling the UK’s NHS and global shipping giant FedEx. The initial outbreak was only halted when a researcher discovered and activated a hardcoded "kill switch" domain.

#### Origin and discovery
**NotPetya:** NotPetya originated from a sophisticated supply chain attack targeting the servers of Linkos Group, a Ukrainian software firm that develops the accounting package M.E.Doc. In early 2017, the Russian military hacking unit Sandworm hijacked these update servers to install a hidden backdoor, which was used to push a malicious update containing the malware on June 27, 2017. Because M.E.Doc is the primary tax software for nearly every business in Ukraine, the malware gained an immediate foothold in thousands of systems across the country's critical infrastructure.

The attack was discovered as reports of rapid, automated infections flooded in from Ukrainian banks, power companies, and airports. Security researchers quickly realized it was not the original Petya; while it shared some code, this version was designed for destruction rather than profit. Researcher Amit Serper was the first to discover a "vaccine" for the malware. He found that the encryption routine would exit if a specific file named `perfc` (with no extension) existed in the `C:\Windows` folder, allowing administrators to manually protect individual machines.

**WannaCry:** The WannaCry outbreak began on May 12, 2017, but its technical roots trace back to the U.S. National Security Agency (NSA). The malware was powered by EternalBlue, a potent exploit targeting a vulnerability in the Windows SMB protocol. This tool was stolen and leaked online in April 2017 by a group known as The Shadow Brokers. While the exploit was American in origin, the U.S. and UK governments later formally attributed the creation of the WannaCry ransomware itself to the Lazarus Group, a state-sponsored hacking collective linked to North Korea.

The attack was discovered in real-time as it crippled organizations globally, most notably the UK’s National Health Service (NHS). The rapid spread was famously halted by security researcher Marcus Hutchins (MalwareTech). While analyzing the code, he found it pinged an unregistered, nonsensical domain. By registering that domain for $10.69, he activated a hardcoded "kill switch" that signaled the malware to stop its self-propagation, preventing millions of further infections.

#### **Target industries**
**NotPetya:** The original target of NotPetya was Ukraine; however, its self-propagating nature caused it to rapidly spread across a wide range of global industries. Because it targeted specific accounting software used for taxes in Ukraine, any multinational company with a local branch or partner there was vulnerable. The most severely impacted industries include: 
1. **Transportation & Logistics:** This was the hardest hit sector: 
- **Global Shipping:** A.P. Moller-Maersk, the world's largest container shipping company, was forced to shut down IT systems at 76 port terminals worldwide.
- **Courier Services:** FedEx's European subsidiary, TNT Express, suffered permanent data loss and delivery delays that lasted for months.
- **Public Transit:** In Ukraine, the Kiev metro system's payment terminals and several airports were paralyzed. 
2. **Critical Infrastructure & Energy:** The attack was specifically designed to destabilize national services in Ukraine. 
- **Energy Sector:** It hit six power companies and the national power grid, causing temporary outages.
- **Nuclear Facilities:** The Chernobyl Nuclear Power Plant had to switch to manual radiation monitoring after its automated systems went offline.
- **Oil & Gas:** Russia's largest oil producer, Rosneft, and several gas station chains reported disruptions to their IT systems. 
3. **Finance & Banking** - **Ukrainian Banks:** The National Bank of Ukraine and at least 22 other banks were hit, causing ATMs across Kiev to stop working and preventing citizens from withdrawing cash. 
4. **Healthcare & Pharmaceuticals**
- **Drug Manufacturing:** Merck & Co. (MSD) saw production of its drugs and vaccines halted, including the Gardasil HPV vaccine, leading to roughly $870 million in damages. 
- **Hospital Systems:** Heritage Valley Health System in Pennsylvania and several hospitals in Ukraine were unable to access patient records or use diagnostic equipment. 
5. **Manufacturing & Consumer Goods**
- **Food & Snacks:** Mondelez International (owner of Oreo and Cadbury) faced total logistics and email shutdowns, resulting in nearly $188 million in lost sales.
- **Consumer Products:** Reckitt Benckiser (owner of Durex and Lysol) had production and shipping halted at several global sites.
- **Construction:** Saint-Gobain, a major French construction materials firm, reported widespread outages costing approximately $384 million. 
6. **Professional Services**
- **Legal:** DLA Piper, one of the world's largest law firms, was knocked offline for days, with lawyers unable to access client files or email.
- **Advertising:** WPP, a global advertising giant, saw its IT systems disrupted across multiple subsidiaries.

**WannaCry:** WannaCry was mostly indiscriminate and spread across the globe as a blanket attack rather than targeting any specific organization. Much like NotPetya, its worm-like capabilities caused massive disruptions in sectors reliant on legacy, unpatched Windows systems. Several sectors were hit particularly hard both operationally and financially: 
- **Healthcare:** Hospitals were among the most visible victims due to the immediate risk to life. In the UK, the National Health Service (NHS) saw one-third of its hospital trusts affected, leading to the cancellation of 19,000 appointments and the diversion of ambulances. 
- **Manufacturing & Automotive:** Major production halts occurred as the malware spread to factory floors. Renault and Nissan were forced to stop production at multiple sites. Later, in 2018, a variant forced TSMC to temporarily shut down chip-fabrication plants. 
- **Logistics & Transportation:** FedEx was a high-profile victim, experiencing significant package delivery delays. In Germany, Deutsche Bahn suffered hijacked departure boards and network outages. 
- **Telecommunications:** Major providers like Spain’s Telefónica, Russia’s MegaFon, and Portugal Telecom were hit early, forcing them to shut down internal systems to contain the spread. 
- **Education:** Over 4,000 academic institutions in Asia, including many in China, reported infections that locked students out of years of research and dissertation work. 
- **Government & Public Sector:** Agencies ranging from the Russian Interior Ministry and Andhra Pradesh Police (India) to various Chinese public security bureaus were crippled.

### Attack Methodology
**NotPetya:** NotPetya evolved from a basic phishing attack into a sophisticated multi-stage ransomworm attack. The process followed these steps:
1. **Initial Infection Vector**
  - **Supply Chain Attack:** The 2017 outbreak began by compromising the update mechanism of M.E.Doc, a tax and accounting software package used by almost every firm doing business in Ukraine.
  - **Phishing:** Original 2016 versions and some 2017 waves used malicious email attachments (often disguised as resumes) containing infected Dropbox links or executable files.
2. **Lateral Movement (Propagation)**
Once a machine within a network was infected, the malware automatically spread without human interaction through several tools: 
  - **EternalBlue & EternalRomance:** Exploited vulnerabilities in the Windows SMBv1 protocol (CVE-2017-0144 and CVE-2017-0145) to infect unpatched machines.
  - **Credential Harvesting:** Used a customized version of Mimikatz to pull administrative passwords and usernames from the infected computer's memory (LSASS).
  - **Legitimate Admin Tools:** Leveraged stolen credentials to spread to patched machines using legitimate Windows tools like PsExec and WMIC.
3. **Payload Execution and Lockout**
  - **MBR/MFT Encryption:** Instead of encrypting individual user files, the malware overwrote the Master Boot Record (MBR) and encrypted the Master File Table (MFT).
  - **Fake Repair Screen:** It triggered a system reboot and displayed a fake "CHKDSK" screen to trick users while it encrypted the drive in the background.
  - **Ransom/Wiper Ruse:** A ransom note eventually appeared, but researchers discovered NotPetya was actually a wiper; it irreversibly scrambled data, and no decryption key existed even if the ransom was paid.

**WannaCry:** The worm-like propagation was a unique feature at the time compared to traditional ransomware. The attack chain followed these steps:
1. **Initial Infection and Discovery**
  - **Vulnerability Exploitation:** The malware identified vulnerable Windows systems by scanning for open TCP port 445.
  - **EternalBlue Exploit:** It used the EternalBlue exploit to target a flaw in the SMBv1 protocol, allowing for remote code execution.
  - **DoublePulsar Backdoor:** Once the exploit was successful, the DoublePulsar tool was often used to install and execute the ransomware payload (the "dropper") in kernel mode for high-level system control. 
2. **The Kill Switch Check:** Before proceeding, WannaCry attempted to connect to a specific, hardcoded, non-existent web domain. 
  - **Failure to Connect:** If the domain was not found (the intended behavior for the attackers), the malware began the encryption process.
  - **Success (Kill Switch):** If the domain was found, as happened after Marcus Hutchins registered it, the malware terminated its execution. 
3. **Execution and Encryption:** If the kill switch was not triggered, the malware performed several automated actions:
  - **Privilege Escalation:** It ran with SYSTEM or Administrator privileges to ensure maximum impact.
  - **Hybrid Encryption:** It used AES-128 to encrypt file data and RSA-2048 to protect the AES keys, making recovery impossible without the private key.
  - **Anti-Recovery:** It deleted Volume Shadow Copies using the command `vssadmin.exe Delete Shadows /All /Quiet` to prevent easy restoration. 
4. **Automated Lateral Movement:** WannaCry's most dangerous feature was its "spreader" component: 
  - **Network Scanning:** It scanned the local subnet and random IP addresses on the public internet for other vulnerable machines.
  - **Worm-like Propagation:** For every unpatched machine it found, it repeated the EternalBlue exploit, effectively "jumping" from one computer to another across the network.

#### **Initial access techniques**
**NotPetya:** The majority of the time, initial access was achieved through highly sophisticated supply chain attacks, though other methods were observed as the malware spread across the world.
1. **Primary Vector: Software Supply Chain Compromise:** The vast majority of initial infections began with the hijacking of the update infrastructure for M.E.Doc, a popular Ukrainian tax and accounting software. 
- **Backdoor Injection:** Attackers (the Sandworm group) gained access to the Linkos Group servers and injected a malicious backdoor into a legitimate software update. 
- **Automatic Distribution:** On June 27, 2017, this poisoned update was pushed automatically to thousands of customers who used M.E.Doc for their mandatory tax filings. 
- **Targeted Reach:** Since almost every business operating in Ukraine was required by law to use this software, it provided the attackers with an immediate foothold in the country's critical infrastructure. 
2. **Secondary Vector: Phishing Emails:** While the supply chain attack was the main vector, some security researchers observed a second wave of infections delivered via phishing emails. 
- **Malicious Attachments:** These emails typically contained infected attachments or links that, when opened by a user, executed the NotPetya payload.
- **Diversification:** This method helped the malware reach organizations that might not have been using the M.E.Doc software directly but were part of the broader interconnected business ecosystem. 
3. **Exploitation of Public-Facing Applications:** In some cases, the malware gained initial access to a network by exploiting the EternalBlue vulnerability (CVE-2017-0144) on internet-facing systems that had not been patched. Once a single vulnerable machine was compromised from the outside, the malware's worm-like capabilities allowed it to rapidly take over the rest of the internal network.

**WannaCry:** Unlike ransomware before it, WannaCry's initial access was not defined by humans clicking on malicious links; it was defined by the automated exploitation of network vulnerabilities. 
1. **No Phishing Required:** While many ransomware strains start with a lure, WannaCry primarily gained access by scanning the internet and local networks for computers with an open Port 445 (SMB). If a machine was connected to the internet and had not installed the MS17-010 security patch, it was vulnerable to immediate infection.
2. **The EternalBlue Exploit:** The key that allowed WannaCry entry was EternalBlue. Developed by the NSA and leaked by the Shadow Brokers, this exploit targeted a flaw in the SMBv1 protocol. It allowed the malware to:
- Send a specially crafted packet to a target machine.
- Trick the system into executing code without any username or password.
- Gain SYSTEM-level privileges (the highest level of control) immediately upon entry.
3. **The "Patient Zero" Mystery:** There is still debate among researchers regarding a "patient zero." Some early reports suggested a small-scale phishing campaign might have dropped the initial payload, which then began its worm-like spreading. However, the vast majority of the 300,000+ infections occurred because the malware found vulnerable machines via network scanning.
4. **Lateral Movement as "Access":** Once WannaCry got inside a corporate network (for example, through a single unpatched laptop connected to public Wi-Fi), it did not need to send emails to reach other computers. It used its spreader module to automatically scan the internal network, exploiting every other unpatched server and workstation it could find within seconds.

#### **Lateral movement**
**NotPetya:** Unlike the original version, which stayed on one computer, NotPetya was an extremely aggressive worm. Once inside a network, usually through the poisoned M.E.Doc update, it did not need any more help from the user to take over other systems. It combined stolen credentials with potent exploits:
1. **The Eternal Exploits (Unpatched Systems):** NotPetya used two leaked NSA exploits to jump across the network to any computer that had not been updated with recent security patches:
- **EternalBlue:** This targeted a flaw in the Windows SMBv1 protocol (file sharing). It allowed the malware to execute code on a remote computer without needing a password.
- **EternalRomance:** A similar exploit that targeted the same file-sharing protocols to gain control of older or unpatched versions of Windows.
2. **Credential Harvesting (Patched Systems):** This was the most effective part of the attack. Even if a company had patched their computers against EternalBlue, NotPetya could still gain entry:
- **Custom Mimikatz:** NotPetya carried a built-in version of a tool called Mimikatz. It reached into the RAM of the first infected computer and "scraped" out usernames and passwords belonging to anyone who had logged in recently; specifically targeting Domain Administrators.
- **Living off the Land:** Once it had those admin passwords, it used legitimate Windows administrative tools like PsExec and WMIC to remotely log into every other computer on the network and install itself. To network security, this appeared to be a normal IT admin performing routine work.
3. **Network Scanning:** The moment it landed on a system, it immediately scanned the local network to find:
- Every active IP address.
- All open SMB ports (Port 445).
- Any "neighbor" computers visible through the local subnet.

Because of this combination, NotPetya could wipe out an entire global network in minutes. At Maersk, for example, the virus spread so fast that IT staff watched their screens go black one by one across the entire office.

**WannaCry:** This is considered the gold standard for automated lateral movement. WannaCry was a true worm, meaning moving around the network was an autonomous process. It achieved this through:
- **The Spreader Mechanism:** Once WannaCry infected a single system on a network, it did not need a human to click anything else. It used a built-in scanning module to move laterally:
  - **Internal Scanning:** It scanned the local subnet (/24) for any other devices with Port 445 (SMB) open.
  - **The Exploit Loop:** For every device it found, it attempted to launch the EternalBlue exploit. If successful, it would immediately install itself on the new machine and start the cycle over.
  - **Speed:** This allowed the malware to jump across an entire office or hospital network in seconds. A single unpatched laptop returning from a coffee shop could infect an entire data center upon connecting to the corporate Wi-Fi.

This was highly effective because:
- **No Credentials Needed:** Traditional lateral movement usually requires stealing an admin password. WannaCry used a buffer overflow in the Windows kernel to force its way in without any authentication.
- **High Privileges:** Because EternalBlue exploited a kernel-level driver (`srv.sys`), the malware gained SYSTEM privileges, the highest possible, the moment it landed on a new machine.
- **Blind Spots:** Many companies patched their internet-facing servers but left internal workstations unpatched. WannaCry proved that once the perimeter is breached, an internal lack of patching is fatal.

#### **Encryption process**
**NotPetya:** Though it was similar to the original version of the malware, NotPetya had additions that turned it into a permanent wiper. The process followed these steps: 
1. **The Low-Level Overwrite (Salsa20):** Just like the original, NotPetya started by overwriting the Master Boot Record (MBR) and forcing a reboot. After the restart, it displayed the fake "CHKDSK" screen while it encrypted the Master File Table (MFT) using the Salsa20 stream cipher.
2. **The Fatal Flaw (The "Wiper" Part):** This is where NotPetya became different and deadly. In the original Petya, the software generated a random key and displayed an ID on the screen that developers could use to provide a decryption key. However, with NotPetya:
- **Discarded Key:** The malware was programmed to generate a random 128-bit string as an "installation ID," but it discarded the actual decryption key immediately after encrypting the disk.
- **Fake ID:** The long string of letters and numbers shown on the ransom screen was just random gibberish. It was not derived from the encryption key, meaning even the hackers who wrote the virus could not help victims get their data back.
- **Irreversible Damage:** Because the MFT was scrambled and the key was deleted, the data on the hard drive was effectively gone forever the moment the "repairing" screen finished. 
3. **File-Level Encryption (AES-128):** While the bootloader was busy locking the disk, the malware also ran a background process within Windows to encrypt specific file types (like .docx, .pdf, .jpg, etc.) using AES-128 encryption.
- **Public Key:** These files were encrypted using a public RSA-2048 key embedded in the malware.
- **No Private Key:** Since the attackers never intended to provide the matching private key, these individual files were also unrecoverable.
4. **Self-Destruction:** After completing the encryption and displaying the ransom note, NotPetya would often clear the system's Event Logs and delete its own traces to make forensic analysis more difficult for security teams. 

**WannaCry:** The process for encryption was highly structured and used a three-tier key hierarchy to ensure the files could not be decrypted without the master private key held by the attackers. The process followed these steps:
1. **The Key Hierarchy:** WannaCry used a combination of RSA-2048 (asymmetric) and AES-128-CBC (symmetric) encryption:
- **The Master Key:** The attackers generated a "Master" RSA key pair. The private half remained on their server.
- **The Victim Key:** Upon infection, the malware generated a unique RSA-2048 "Victim" key pair locally on the computer.
- **The File Key:** For every individual file encrypted, a new, random 128-bit AES key was generated.
2. **The Step-by-Step Flow**
- **Preparation:** The malware first attempts to terminate processes related to databases and Microsoft Office to ensure no files are "in use" or locked.
- **Symmetric Encryption:** It reads a file and encrypts its content using the AES-128 key.
- **Key Wrapping:** It then encrypts (wraps) that specific AES key using the Victim’s RSA Public Key.
- **Header Attachment:** The encrypted AES key and a specific "WANACRY!" magic string are prepended to the encrypted file data.
- **Final Protection:** The Victim’s RSA Private Key (needed to unwrap the AES keys) is itself encrypted using the Master RSA Public Key and stored on the disk.
3. **Disruption of Recovery:** To ensure the victim had no choice but to pay, WannaCry executed several commands to destroy recovery options:
- **Shadow Copy Deletion:** It ran `vssadmin.exe Delete Shadows /All /Quiet`.
- **Boot Fix Disabling:** It disabled Windows recovery features using `bcdedit /set {default} recoveryenabled No`.
- **Backup Deletion:** It used `wbadmin` to delete any existing system state backups.
4. **File Transformation:** The original files were overwritten or deleted, and the new encrypted versions were given the extension `.wncry`. Because the private key needed to start the decryption chain was itself encrypted by the attackers' master key, the files remained locked until a ransom was paid and a decryption tool was sent back.

### Indicators of Compromise (IoC)
**NotPetya:** Unlike the original Petya, NotPetya's IoCs are characterized by its worm-like propagation and the abuse of legitimate Windows Admin tools. These IoCs include:

#### **File-Based Indicators**
- **perfc.dat:** The primary malware payload, typically a 32-bit Windows DLL. It is often dropped in `C:\Windows\`. Note that it must be executed via `rundll32.exe` using its ordinal (such as `rundll32.exe C:\Windows\perfc.dat,#1`).
- **dllhost.dat:** A copy of the PsExec utility used for remote execution during lateral movement.
- **Random .tmp files:** Found in the `%TEMP%` directory, these contain the custom Mimikatz module used for credential harvesting.
- **Known File Hash (SHA-256):** `027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745`

#### **System & Registry Indicators**
- **Scheduled Task for Reboot:** A task created to restart the system via `shutdown.exe` to trigger the MFT encryption phase.
- **Clearing Event Logs:** The malware uses `wevtutil cl Setup`, `wevtutil cl System`, and `wevtutil cl Security` to erase evidence of its arrival.
- **Registry Run Key:** A persistence mechanism often found at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` pointing to the malicious payload.

#### **Network & Lateral Movement Indicators**
- **SMBv1 Exploitation:** Unusual spikes in Port 445 traffic as the malware attempts EternalBlue and EternalRomance exploits.
- **Remote Admin Activity:** Unauthorized use of `PsExec` or `WMIC` to execute commands on remote systems.
- **Credential Harvesting:** Unauthorized processes interacting with `lsass.exe` to extract plaintext passwords or NTLM hashes.
- **Known Malicious Domain:** `www.1dnscontrol.com` associated with the malware infrastructure.

#### **Behavioral "Vaccine" (Kill Switch)**
NotPetya checks for the existence of its own filename in the `C:\Windows\` directory before executing. Creating a read-only file named `perfc` (with no extension) in `C:\Windows\` can prevent the malware from running on that specific machine.

**WannaCry:** To catch WannaCry before encryption completes, defenders look for aggressive network behavior and specific kernel-level artifacts:
1. **The Kill Switch Domain:** The malware attempts to contact a hardcoded, unregistered domain before executing. If the connection is successful, the malware exits.
- `www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`
- `www.iffp9ofjdf9kgur9p0ifjdf9kgur9p0f.com` (Later variant)
2. **SMB Exploitation & Network Scanning:** WannaCry is highly visible on the network:
- **Port 445 Spikes:** Massive outbound traffic as the worm scans local subnets and random public IP ranges.
- **EternalBlue Artifacts:** Detection of "Trans2" SMB packets designed to trigger a buffer overflow in the `srv.sys` driver.
- **DoublePulsar Backdoor:** An SMB response with a "Multiplex ID" of 0x41 indicates the kernel-level backdoor is active.
3. **File System & Process Artifacts**
- **tasksche.exe:** The main executable often renames itself to `tasksche.exe` and runs from `C:\Windows\` or `C:\ProgramData\`.
- **The .wncry Extension:** Encrypted files are appended with the `.wncry` or `.wncryt` extension.
- **The "WANACRY!" Header:** Every encrypted file begins with the 8-byte magic string `57 41 4e 41 43 52 59 21`.
4. **System Commands (Indicators of Attack)**
- `vssadmin.exe Delete Shadows /All /Quiet`
- `bcdedit /set {default} recoveryenabled No`
- `wbadmin delete systemstatebackup`
5. **Mutexes:** WannaCry uses specific Mutexes to prevent multiple infections on the same host:
- `Global\MsWinZonesCacheCounterMutexA`
- `Global\MsWinZonesCacheCounterMutexA0`

### Special Features
**NotPetya:** Significantly different from the original Petya, NotPetya dropped business features like affiliate programs and added high-end military-grade features intended for maximum speed and destruction. These included: 
- **Supply Chain Attack**
  - This was NotPetya's "Patient Zero" feature. It did not rely on emails; it hijacked the update server of M.E.Doc. When users downloaded a legitimate software update, they unknowingly invited the malware into their network. This gave the attackers (the Sandworm group) immediate access to thousands of high-value targets.
- **Worm-like Propagation (The Ransomworm)**
  - Unlike the original, NotPetya was fully automated. It used the EternalBlue and EternalRomance exploits to jump from one computer to another without human interaction. It could clear an entire global office network in minutes.
- **Credential Harvesting (Mimikatz)**
  - Even if a computer was patched against exploits, NotPetya had a workaround. It carried a built-in version of Mimikatz to scrape passwords from the memory (LSASS process) of infected machines. It then used those stolen admin credentials to log into other "safe" computers using legitimate Windows tools like PsExec and WMIC.
- **State-Sponsored Wiper (Data Destruction)**
  - The most unique feature was that it was a fake. While it appeared to be ransomware, it was actually a wiper. It was designed to permanently destroy data by discarding the decryption key. There was no way to recover files, even if the ransom was paid.
- **Low-Level Disk Hijacking**
  - Inherited from the original Petya, this feature allowed the malware to bypass the Windows OS. By overwriting the Master Boot Record (MBR), it could encrypt the drive's "map" (the MFT) before Windows even finished loading.

**WannaCry:** WannaCry was a landmark event because it combined state-sponsored weapons with criminal extortion. Its features were distinct from the corporate style of modern ransomware: 
- **Worm-like Propagation:** This was WannaCry's defining feature. Unlike previous ransomware that required a human to click a link, WannaCry used the EternalBlue exploit to move autonomously. It scanned both local networks and the public internet for vulnerable SMB (Port 445) ports, allowing it to jump between computers without user interaction.
- **The Kill Switch:** Unique among major malware, WannaCry had a hardcoded safety check. Before encrypting, it would attempt to connect to a specific, unregistered web domain. If the connection succeeded, the malware would self-terminate. This was likely an anti-sandbox measure that backfired when Marcus Hutchins registered the domain, halting the global outbreak.
- **Kernel-Mode Execution (DoublePulsar):** WannaCry did not just run as a normal program; it often leveraged the DoublePulsar backdoor to gain kernel-level privileges. This allowed the malware to run with the highest possible permissions, making it significantly harder for standard antivirus software to terminate the process once it started.
- **Multilingual Ransom Interface:** To maximize global reach, the "WanaDecryptor" interface supported 28 different languages. It would automatically detect the system's language setting to display instructions the victim could understand, increasing the likelihood of payment.

### Real-World Incidents
**NotPetya:** NotPetya is considered one of the most destructive cyberattacks in history, causing an estimated $10 billion in total damages globally. Though it primarily targeted Ukraine, its worm-like capabilities allowed it to jump across global networks, crippling some of the world's largest companies. Major incidents include: 
1. **The Near-Collapse of Maersk (Shipping):** The Danish shipping giant, responsible for nearly one-fifth of the world’s shipping capacity, was rendered "dead in the water" within minutes of the attack. 
- **Impact:** The virus wiped 45,000 PCs and 4,000 servers, forcing the company to reinstall its entire global IT infrastructure in just 10 days.
- **The "Ghana Miracle":** Maersk's entire network was almost permanently lost because every domain controller was wiped simultaneously. They were saved by a power outage in Ghana that had knocked one lone domain controller offline, leaving its data uninfected. A staffer had to fly the hard drive from Ghana to London to begin the rebuild.
- **Cost:** Estimated at $250M–$300M. 
2. **Merck & Co. (Pharmaceuticals):** The U.S. pharmaceutical giant suffered the highest reported individual financial loss from the attack. 
- **Impact:** The malware crippled manufacturing, research, and sales operations. It specifically halted the production of the Gardasil (HPV) vaccine, forcing the company to borrow doses from the CDC to meet patient demand.
- **Cost:** Approximately $870 million. 
3. **Total Paralysis of Ukraine (Critical Infrastructure):** NotPetya acted as a digital bomb on Ukraine's systems, hitting the country on the eve of its Constitution Day. 
- **Government & Finance:** The attack wiped data at 22 banks, four hospitals, and practically every federal agency.
- **Chernobyl:** Radiation monitoring systems at the Chernobyl nuclear site were knocked offline, forcing scientists to switch to manual monitoring with handheld sensors.
- **Daily Life:** ATMs, point-of-sale systems at gas stations, and the Kiev Metro payment systems were all disabled simultaneously. 
4. **FedEx/TNT Express (Logistics):** FedEx's European subsidiary, TNT Express, was severely hit, leading to permanent data loss in some systems. 
- **Impact:** The company had to resort to manual processes for months to clear the delivery backlog.
- **Cost:** Estimated at $400 million. 
5. **Other Major Corporate Casualties**
- **Saint-Gobain (Construction):** The French materials giant suffered $384M in losses after widespread system outages.
- **Mondelez (Food):** The maker of Oreo and Cadbury faced $188M in damages. This incident sparked a landmark legal battle when their insurer denied the claim, citing a "war exclusion" clause.
- **Reckitt Benckiser (Consumer Goods):** The owner of Lysol and Durex lost roughly $129M due to halted production and shipping.

**WannaCry:** The impact of WannaCry was severe because its worm-like nature allowed it to paralyze large-scale infrastructure in minutes. While more than 200,000 computers were affected in over 150 countries, these incidents stand out:
1. **UK National Health Service (NHS):** This was the most high-profile casualty. The attack crippled nearly one-third of NHS hospital trusts in England. 
- **Operational Collapse:** Staff were forced to use pen and paper as digital systems, including patient records and MRI scanners, went dark.
- **Patient Risk:** Over 19,000 appointments were canceled, and five major hospitals had to divert emergency ambulances to other facilities.
- **Cost:** Total disruption and subsequent IT upgrades cost the NHS an estimated £92 million. 
2. **Global Logistics & FedEx:** FedEx was one of the few major U.S.-based companies hit. The malware infected its TNT Express subsidiary, causing significant interference with electronic delivery systems. 
- **Service Delays:** FedEx had to suspend its money-back guarantees for packages during the outbreak.
- **Long-term Impact:** This incident, combined with the subsequent NotPetya attack, cost the company hundreds of millions in lost revenue and remediation. 
3. **Manufacturing & Automotive:** Production lines were halted to prevent the worm from spreading further.
- **Renault & Nissan:** Renault stopped production at several sites, while Nissan’s manufacturing plant in northeast England was also affected. 
- **TSMC (2018 Variant):** A year later, a variant of WannaCry (often attributed to improper tool patching) infected 10,000 machines at Taiwan Semiconductor Manufacturing Company, forcing a temporary shutdown of several chip-fabrication plants. 
4. **Critical Infrastructure & Public Services**
- **Deutsche Bahn (German Railways):** While trains continued to run, arrival and departure boards at stations across Germany were hijacked, displaying the red ransom note. 
- **Russian Ministry of Interior:** Approximately 1,000 computers at the ministry were infected, though officials claimed no sensitive data was compromised. 
- **Telefónica:** The Spanish telecom giant was one of the first major companies hit, forcing its headquarters to tell all employees to shut down their computers immediately. 
5. **Education & Small Scale** - **Asian Universities:** Over 4,000 schools and universities in Asia were hit, with thousands of students reportedly losing years of work on research and dissertations.

### Relevant Photos
* [NotPetya Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/14_NotPetya_Ransom_Note.webp)
* [WannaCry Ransom Note GUI](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/15_WannaCry_Ransom_Note.png)

---

## GandCrab: 2018
### Overview
GandCrab was a dominant Ransomware-as-a-Service (RaaS) operation that infected over 1.5 million victims between 2018 and 2019. Known for demanding Dash cryptocurrency and using the .bit TLD to evade detection, it operated via affiliates who split ransom profits with the developers. Though the group claimed to "retire" after extorting an estimated $2 billion, researchers believe they rebranded into the notorious REvil (Sodinokibi) group. Free decryptors for most versions are now available through the No More Ransom project.

#### Origin and discovery
The GandCrab ransomware first surfaced on January 28, 2018, when it was advertised on Exploit.in, a prominent Russian-language cybercrime forum. It was initially discovered by security researcher David Montenegro and experts at the cybersecurity firm LMNTRIX. Unlike many previous ransomware strains that remained in development for months, GandCrab's creators adopted an "agile" approach, releasing a minimally viable version and then rapidly iterating based on feedback and security researcher countermeasures. 

The discovery of the group's infrastructure early on led to a significant breakthrough in February 2018. Researchers at Bitdefender, working with Europol and the Romanian Police, discovered a vulnerability in the ransomware's command-and-control (C2) servers. This breach allowed law enforcement to leak the private decryption keys for the first version of the malware, leading to the release of the first free decryptor just one month after the threat emerged. However, the developers responded within a week by hardening their servers and releasing GandCrab v2, sparking a long-running "cat-and-mouse" game with the global security community.

#### Target industries
GandCrab was known for being indiscriminate and targeting any Windows user, though it specifically shifted from individual consumers to high-value organizations to maximize ransom payouts. The most frequently targeted sectors included: 
- **Managed Service Providers (MSPs):** Attackers exploited vulnerabilities in remote IT management tools (like Kaseya and ConnectWise) to infect all of an MSP’s clients simultaneously. 
- **Healthcare:** Hospitals and medical clinics were primary targets because their urgent need for data access made them more likely to pay large ransoms quickly. 
- **Government & Public Sector:** Notable victims included local governments in the United States (such as Jackson County, GA) and government departments in China and Vietnam. 
- **Manufacturing:** Large industrial firms were targeted due to the high cost of operational downtime, which pressured them into paying. 
- **Professional Services:** Legal, financial, and engineering firms were frequently hit because they handle sensitive, high-value intellectual property and client data. 

##### **Common Victim Profile:**
- **Geography:** Most victims were located in Europe, North America, and Asia (specifically Japan and Vietnam).
- **Excluded Regions:** The malware explicitly avoided infecting systems in Russia or former Soviet Union (CIS) countries.

### Attack Methodology
GandCrab relied on high-speed agility in its development cycle and a wide range of delivery vectors to bypass traditional security. This included:
1. **Initial Access & Delivery:** Because it was a Ransomware-as-a-Service (RaaS), the delivery method often depended on the specific affiliate conducting the attack. 
- **Phishing & Malspam:** The most common vector, using deceptive emails with subject lines like "Unpaid invoice" and attachments containing malicious ZIP files, PDFs, or Word documents with embedded macros. 
- **Exploit Kits:** Malicious scripts on compromised websites (often WordPress) would automatically scan for and exploit unpatched vulnerabilities in a user’s browser or Flash Player (such as the RIG and GrandSoft exploit kits). 
- **RDP Brute Forcing:** For more targeted attacks, hackers would gain direct access by brute-forcing weak Remote Desktop Protocol (RDP) credentials or buying them on dark web forums. 
2. **Execution and Stealth:** Once inside, the malware performed several automated checks to ensure a successful infection:
- **System Reconnaissance:** It gathered the computer name, OS version, and installed antivirus software.
- **AV Interference:** It specifically searched for and attempted to shut down or delete security programs like AhnLab’s V3 Lite to prevent detection.
- **Anti-Analysis:** It used techniques like "API hammering" to make sandboxes time out and "anti-disassembly" tricks to frustrate human researchers.
- **Persistence:** It typically added itself to the Windows "RunOnce" registry key to ensure it would resume encryption even if the system rebooted. 
3. **Encryption Process**
- **Key Generation:** GandCrab generated a unique RSA-2048 public/private key pair for the victim. It then used AES-256 (or Salsa20 in later versions) to encrypt individual files with a unique key for each one. 
- **File Locking:** It first killed processes that might be holding files open (like SQL, Outlook, or Office) to ensure it could encrypt as much data as possible. 
- **Backup Deletion:** Finally, it deleted Windows Shadow Copies (automated backups) using commands like `vssadmin` or `wmic` to prevent the victim from restoring files for free. 
4. **Communication (C2):** The malware used the .bit Top-Level Domain (TLD) for its command-and-control servers, which is decentralized via Namecoin and harder for authorities to shut down. It sent the victim's unique decryption key to these servers via encoded HTTP requests.

#### **Initial access techniques**
Because this was a RaaS, the initial access techniques varied widely depending on the preferences and skills of the individual affiliates who were distributing it. Some of the most common methods include:
- **Phishing and Malspam:** Affiliates frequently sent mass emails with deceptive subject lines like "Unpaid Invoice" or "Emergency Exit Map." These emails contained malicious attachments, such as ZIP archives with obfuscated JavaScript or VBScript, or Office documents with weaponized macros that downloaded the ransomware payload upon execution. 
- **Exploit Kits (EKs):** This was a signature delivery method for GandCrab. Malicious advertisements (malvertising) or compromised websites would redirect users to landing pages hosting exploit kits like RIG, GrandSoft, Magnitude, and Fallout. These kits automatically scanned the visitor's browser for unpatched vulnerabilities; primarily in Adobe Flash, Internet Explorer, or Adobe Reader; to trigger a "drive-by download" without user interaction. 
- **Remote Desktop Protocol (RDP) Intrusion:** In more targeted "big game hunting" attacks, hackers gained access by brute-forcing weak RDP credentials or purchasing previously stolen login info from dark web marketplaces. This allowed them to manually log into a server, perform reconnaissance, and deploy the ransomware across the entire network. 
- **Vulnerability Exploitation:** Some campaigns leveraged specific server-side vulnerabilities to gain entry, including flaws in Oracle WebLogic (CVE-2019-2725), Apache Struts, and JBoss. In its later stages, versions were even seen using the EternalBlue SMB exploit to spread laterally through networks. 
- **Software Supply Chain & MSPs:** Affiliates occasionally compromised Managed Service Providers (MSPs) by exploiting vulnerabilities in their remote management tools (such as Kaseya VSA or ConnectWise Control), allowing them to push GandCrab to all of the provider's downstream customers simultaneously.

#### **Lateral movement**
In the early versions, GandCrab was mostly opportunistic and lacked built-in lateral movement capabilities. As it evolved into a tool for high-value targets, it adopted several methods of lateral movement:
1. **Manual "Hands-on-Keyboard" Movement:** For high-value targets like MSPs, attackers did not rely on automation. Instead, they performed manual lateral movement:
- **Credential Harvesting:** Attackers used tools like Mimikatz to dump plaintext passwords or NTLM hashes from the memory (LSASS) of the initially compromised machine. 
- **Remote Desktop Protocol (RDP):** Using stolen credentials, they manually logged into other servers and workstations on the network to disable security software and deploy the ransomware. 
- **Administrative Tools:** They leveraged legitimate system tools, a technique known as "Living off the Land"; including `PsExec`, `WMI`, and PowerShell to execute commands and distribute the payload to remote hosts. 
2. **Automated Self-Propagation (v4 and v5):** Later variants introduced features that allowed the malware to spread automatically without human intervention: 
- **EternalBlue SMB Exploit:** Starting with GandCrab v4, the malware was updated to include the EternalBlue exploit. This allowed it to scan the local network for unpatched Windows systems and infect them via the SMB protocol. 
- **Network Share Scanning:** The ransomware would systematically enumerate all accessible network shares (logical drives from A: to Z:) to encrypt files stored on central servers and connected backup drives. 
3. **Supply Chain Exploitation:** One of GandCrab's most devastating methodologies involved compromising MSPs. By gaining access to an MSP’s remote monitoring and management (RMM) console, attackers could push the ransomware to hundreds of downstream client networks simultaneously, effectively moving laterally from the service provider to all its customers in a single action.

#### Encryption process
The encryption process for GandCrab was a multi-layered routine that evolved over the years to prioritize speed and evasion. This included:
1. **Key Generation and Hierarchy:** Before encrypting any user data, the malware established a cryptographic chain of command: 
- **Victim-Specific Keys:** It generated a unique RSA-2048 public/private key pair directly on the victim's machine using the Microsoft Enhanced Cryptographic Provider (CryptoAPI). 
- **Master Key Protection:** The victim's private key was then encrypted using a second "master" RSA public key that was hardcoded into the malware by the developers. 
- **C2 Communication:** In early versions, this encrypted private key was sent to the command-and-control (C2) server before encryption could start. Later versions (v4.0+) removed this requirement, allowing for offline encryption. 
2. **File-Level Encryption:** The malware followed a hybrid encryption approach, combining asymmetric (RSA) and symmetric algorithms: 
- **Individual File Keys:** For every single file targeted, GandCrab generated a random, unique symmetric key and a nonce/IV. 
- **Algorithm Shift:**
  - **Versions 1 through 3:** Used AES-256-CBC.
  - **Versions 4 and 5:** Switched to Salsa20, a stream cipher chosen because it is significantly faster and easier to implement in code than AES.
- **Final Locking:** Each file's unique symmetric key was then encrypted using the victim's RSA-2048 public key and appended to the end of the encrypted file. This ensured that only someone with the matching private key, held by the attackers, could unlock the data. 
3. **Performance Optimization:** To maximize damage before a user could react, GandCrab implemented several efficiency measures:
- **Partial Encryption:** To speed up the process on large systems, later versions often encrypted only the first 1MB of a file rather than the entire content. 
- **Multi-Threading:** It spawned multiple threads to simultaneously encrypt local drives (A: through Z:) and network shares. 
- **Process Killing:** It automatically terminated database and mail software (such as SQL or Outlook) to release file locks and ensure every critical document could be encrypted.

### Indicators of Compromise (IoC)
The IoCs for GandCrab are generally specific to the version, as the developers rapidly updated their code to avoid detection and evade security filters. These include:
1. **File Extensions by Version:** You can often identify the specific variant of GandCrab by the extension it appends to encrypted files: 
- **Version 1:** `.GDCB`
- **Versions 2 and 3:** `.CRAB`
- **Version 4:** `.KRAB`
- **Version 5 (including v5.2):** Randomized 5 to 10 letter uppercase extensions (such as `.UKCZA`, `.YIAQDG`, or `.HHFEHIOL`). 
2. **Network Indicators (C2 Domains):** GandCrab famously used the .bit Top-Level Domain (TLD), which requires specialized DNS resolution (often using `a.dnspod.com` or `ns1.virmach.ru`). 
- **Common C2 Domains:** `gandcrab.bit`, `gdcb.bit`, politiaromana.bit`, `malwarehunterteam.bit`, `zonealarm.bit`, and `ransomware.bit`.
- **Ransom Payment Portals:** Usually hosted on Tor (such as gandcrab2774xx.onion). 
3. **Host-Based Indicators**
- **Registry Persistence:** The malware often adds itself to the `RunOnce` key: 
  - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- **File Paths:** Look for random 6-character executables in the `%APPDATA%` or `%TEMP%` directories: 
  - `%APPDATA%\Microsoft\<random>.exe`
- **Ransom Notes:** Look for text files named `GDCB-DECRYPT.txt`, `KRAB-DECRYPT.txt`, or `<EXT>-DECRYPT.txt` (where `<EXT>` matches the randomized file extension). 
4. **Malicious Hashes (Examples)**
- **v5.1 SHA256:** `0741e7c0b02f6ef0b28d00a7467bf91edb0cb0f6f20dc1fbed76119c7ae79b4f`
- **v5.2 SHA256:** `329b3ddbf1c00b7767f0ec39b90eb9f4f8bd98ace60e2f6b6fbfb9adf25e3ef9`

### Special Features
GandCrab was a trendsetter in many areas of cybercrime; it primarily operated just before the widespread adoption of triple extortion and dedicated data leak sites. Some of these features included:
1. **Affiliate Program (RaaS):** GandCrab was the gold standard for the Ransomware-as-a-Service (RaaS) model. 
- **The Franchise Model:** Developers provided the malware and a 24/7 support panel; affiliates handled the infections.
- **Profit Sharing:** Affiliates typically kept 60% to 70% of the ransom, while the developers took a 30% to 40% cut as a service fee.
- **Support Services:** It was famous for providing live chat support for victims to help them buy cryptocurrency and use the decryptor. 
2. **Supply Chain Attacks and MSP Targeting:** In 2019, GandCrab shifted toward Big Game Hunting by targeting Managed Service Providers (MSPs). 
- **Vulnerability Exploitation:** Attackers exploited a flaw in a ConnectWise plugin for the Kaseya VSA remote management tool.
- **Mass Infection:** By compromising a single MSP, they could bypass individual client defenses and push the ransomware to every endpoint the MSP managed simultaneously. 
3. **Worm-like Propagation:** Later versions of GandCrab introduced automated spreading capabilities to move through networks without human help. 
- **EternalBlue:** Starting with v4, it integrated the EternalBlue (SMB) exploit to move laterally across unpatched Windows systems.
- **Phorpiex Botnet:** It was also distributed via the Phorpiex worm, which allowed it to spread via infected USB drives and removable storage. 

### Real-World Incidents
GandCrab was responsible for more than 1.5 million infections, though its spray and pray approach meant that many victims were home users. In 2019, the affiliates shifted towards big game hunting, which led to several high profile incidents:
1. **Managed Service Provider (MSP) Supply Chain Attacks:** One of GandCrab’s most devastating methodologies involved compromising IT service providers to reach multiple downstream clients at once.
- **The ConnectWise/Kaseya Plugin Breach (2019):** In February 2019, attackers exploited a vulnerability in a ConnectWise plugin for Kaseya VSA. This allowed them to bypass individual client defenses and push GandCrab ransomware to nearly 2,000 systems managed by a single MSP. Reports indicated at least one mid-sized MSP had all 80 of its clients infected simultaneously. 
2. **Healthcare Sector Impact:** GandCrab frequently targeted medical facilities due to the critical nature of their data.
- **Springhill Medical Center (2019):** A GandCrab attack in July 2019 shut down the IT infrastructure of this Alabama hospital for weeks. This incident later became the subject of a high-profile lawsuit, as it was alleged that the IT failure contributed to a fatal diminished care scenario. 
- **Dental Office Waves (2019):** Multiple waves of attacks specifically targeted dental practices in the U.S. By compromising the remote management tools used by dental IT providers, GandCrab affiliates successfully locked the patient records of hundreds of dental offices in a single campaign. 
3. **Government and Municipal Targets**
- **Jackson County, Georgia (2019):** In March 2019, GandCrab crippled the county's entire IT network. The sheriff's office was forced to use pen and paper for arrest bookings, and the county ultimately paid a $400,000 ransom in Bitcoin to regain access to their data. 
4. **The "Syrian Children" Incident:** In a rare moment of mercy, the GandCrab developers released free decryption keys specifically for victims in Syria. This occurred after a Syrian father tweeted that the ransomware had encrypted the only remaining photos of his deceased children and he could not afford the $600 ransom.

### Relevant Photos
* [GandCrab Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/16_GandCrab_Ransom_Note.jpg)
* [GandCrab Wallpaper and File Header](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/17_GandCrab.jpg)

---

## Maze: 2019
### Overview
Maze ransomware is a notorious strain of malware that gained infamy in 2019 for pioneering the double extortion tactic. Unlike traditional ransomware that only locks files, Maze first steals sensitive data and threatens to leak it on a public website if the ransom is not paid. Although the group officially claimed to shut down in late 2020, its legacy lives on through successor groups like Egregor and Sekhmet, which continue to use its aggressive techniques against high-value corporate targets.

#### Origin and discovery
Maze ransomware was first identified on May 29, 2019, by Jérôme Segura, a threat intelligence analyst at Malwarebytes. At the time of its discovery, it was not yet known as Maze; instead, researchers referred to it as `ChaCha` ransomware because it utilized the `ChaCha20` stream cipher for file encryption. Early versions often used a generic ransom note titled "0010 System Failure 0010" and relied on an email address for communication rather than the sophisticated leak sites that would later define the group's brand. 

The transition from a standard malware strain to the infamous Maze brand occurred shortly after its discovery in mid-2019. The operators, a group known by security firms like CrowdStrike as Twisted Spider, began shifting from broad, automated campaigns to highly targeted big game hunting. In November 2019, they officially adopted the Maze name and launched their dedicated dark web leak site, Maze News. This marked the first time a ransomware group systematically used stolen data as secondary leverage for extortion, a move that permanently changed the ransomware threat landscape. 

#### Target industries
For the most part, Maze was quite indiscriminate with who it targeted; although it became famous for big game hunting later, as it was actively seeking out high-value organizations with enough resources to pay million dollar plus ransoms. No sector was immune, and they most frequently targeted:
- **Financial Services and Insurance:** Often targeted via specialized email campaigns, including banks and credit unions. 
- **Healthcare:** A major focus for the group, particularly during the COVID-19 pandemic, despite their public (and later broken) promise not to attack medical providers. 
- **IT Services and MSPs:** By attacking Managed Service Providers (MSPs) like Cognizant, they could gain lateral access to hundreds of the MSP's clients simultaneously. 
- **Manufacturing and Engineering:** This sector was hit frequently due to its reliance on uninterrupted operations and valuable intellectual property. 
- **Government and Public Sector:** Targets included local governments (like the City of Pensacola) and state agencies. 
- **Technology and Professional Services:** Major corporate victims included legal firms, telecommunications companies, and tech giants like Canon, Xerox, and LG Electronics.

### Attack Methodology
Maze utilized a sophisticated, multi-stage lifecycle that primarily focused on long-term persistence as well as maximum leverage through data theft. As opposed to previous strains of malware that would immediately encrypt files, Maze operators would remain in a network for weeks before officially activating. Here is what the process looked like:
1. **Initial Access:** Attackers gained a foothold through several common vectors: 
- **Phishing and Malspam:** Emails with malicious Word or Excel attachments containing macros.
- **Remote Desktop Protocol (RDP):** Using brute-force attacks or stolen credentials to log into internet-facing servers.
- **Vulnerability Exploitation:** Targeting unpatched software, particularly Pulse Secure VPN (`CVE-2019-11510`) and Citrix ADC/Gateway (`CVE-2019-19781`).
- **Exploit Kits:** Using kits like Fallout and Spelevo to target browser or Flash vulnerabilities. 
2. **Reconnaissance and Lateral Movement:** Once inside, the operators mapped the network to identify high-value targets: 
- **Tools:** They used legitimate administrative and security tools like `BloodHound`, `Adfind`, and `PingCastle` to map Active Directory and find vulnerabilities.
- **Credential Theft:** Tools like `Mimikatz` and `Procdump` were used to harvest local credentials, password hashes, and Kerberos tickets.
- **Movement:** Attackers spread through the network using `Cobalt Strike BEACON`, `PsExec`, and PowerShell to execute code on remote machines. 
3. **Privilege Escalation and Persistence:** To ensure they could encrypt the entire network, they wanted Domain Admin privileges. They maintained access by: 
- Installing backdoors to regain entry if their initial presence was detected.
- Creating new privileged domain accounts for ongoing control. 
4. **Data Exfiltration (The Extra Twist):** Before any encryption occurred, the group stole massive amounts of sensitive data (often 100GB to 10TB): 
- **Method:** They used `rclone`, `WinSCP`, `7zip`, or PowerShell scripts to upload files to attacker-controlled FTP servers or cloud storage like Mega.nz.
- **Leverage:** This data was used for double extortion; threatening to leak it on their dark web site if the ransom for the decryption key was not paid. 
5. **Final Encryption and Impact:** The attack concluded with the deployment of the ransomware payload: 
- **Shadow Copy Deletion:** They used the command `vssadmin.exe delete shadows /all /quiet` to delete Windows shadow copies, preventing easy data restoration.
- **Encryption:** Files were locked using a combination of `RSA-2048` and `ChaCha20` algorithms.
- **Notification:** The malware changed the system desktop wallpaper and sometimes played a pre-recorded audio file to alert the victim that they had been hacked. 

#### Initial access techniques
Although Maze's techniques evolved over time, it utilized several specific techniques to gain initial access. The primary methods included:
- **Remote Desktop Protocol (RDP) Exploitation:** This was a frequent vector where attackers gained direct access by using stolen credentials or performing brute-force attacks against unsecured, internet-facing RDP servers. 
- **Phishing and Malspam:** The group heavily used malicious email campaigns. These emails typically contained: 
  - **Weaponized Attachments:** Microsoft Word or Excel documents with malicious macros that, when enabled, downloaded the ransomware or a secondary payload like `Cobalt Strike Beacon`.
  - **Deceptive Themes:** Common subjects included missed package deliveries or fake wireless bills from companies like AT&T.
- **Vulnerability Exploitation:** Maze targeted unpatched, internet-facing services to bypass perimeters. Key targeted vulnerabilities included: 
  - Pulse Secure VPN (`CVE-2019-11510`).
  - Citrix ADC/Gateway (`CVE-2019-19781`).
  - Microsoft Internet Explorer (`CVE-2018-8174`).
- **Exploit Kits:** In its early stages, Maze was frequently distributed via Fallout and Spelevo exploit kits. These kits were hosted on compromised websites and exploited vulnerabilities in software like Flash Player or the Windows VBScript Engine to infect users through drive-by compromises. 
- **Supply Chain and Partners:** In some instances, the initial breach originated from a compromised partner or client of the actual target organization.

#### Lateral movement
Maze would follow a methodical process as it would move laterally, generally spending days or weeks within a network before the final payload was deployed. The intention was identification of high-value data and the acquisition of Domain Admin privileges for maximum impact. The methods included:
- **Cobalt Strike BEACON:** This was the group's primary tool for maintaining a foothold and pivoting across the network. They often deployed multiple beacons across various workstations and servers using malleable C2 profiles to blend in with legitimate traffic. 
- **Credential Harvesting:** Attackers used `Mimikatz` and `Procdump` to dump plaintext passwords, hashes, and Kerberos tickets from memory. They also scanned local drives for files containing "password" and targeted password managers like KeePass. 
- **Network Enumeration:** To map the network, they used specialized tools like `Adfind`, `BloodHound`, and `PingCastle` to identify critical assets such as domain controllers and file servers. 
- **Living off the Land (LotL):** They heavily utilized built-in Windows utilities to blend in with legitimate traffic: 
  - **PsExec and WMI:** Used to execute commands and scripts on remote systems.
  - **PowerShell:** Leveraged for reconnaissance, credential theft, and eventually distributing the ransomware binary.
  - **RDP (Remote Desktop Protocol):** Once credentials were stolen, they used RDP to manually log into systems. They sometimes used the `ngrok` utility to tunnel RDP traffic or `tscon` to hijack existing sessions.

The general attack chain looked like this: 
1. **Reconnaissance:** Scanning Active Directory and identifying open SMB shares.
2. **Privilege Escalation:** Moving to new machines to harvest more credentials until reaching a Domain Admin account.
3. **Broad Distribution:** Using batch scripts combined with `PsExec` or WMI to copy the ransomware binary to hundreds or thousands of hosts simultaneously.

#### Encryption process
Maze utilized a sophisticated, multi-layered encryption scheme, combining symmetric and asymmetric cryptography. This helped ensure files were not able to be recovered without the attacker's unique keys. The process looked like this:
1. **The Multi-Level Cryptographic Scheme:** The process is structured into three distinct levels that aim for speed and security:
- **Level One (File Level):** Individual files are encrypted using the `ChaCha20` stream cipher. The malware generates a unique 32-byte key and an 8-byte nonce for each file.
- **Level Two (Session Level):** The unique `ChaCha20` keys and nonces are then encrypted using a Session `RSA-2048` public key, which is generated locally on the victim's machine when the ransomware is first launched.
- **Level Three (Master Level):** The corresponding Session `RSA-2048` private key is itself encrypted using the Master `RSA-2048` public key hardcoded into the Maze binary. This encrypted session key is then stored in the ransom note. 
2. **Operational Steps during Encryption:** Before and during the file-locking process, the malware performs a few other critical actions: 
- **Shadow Copy Deletion:** Through the use of `WMIC` and `vssadmin` commands, Windows Shadow copies are deleted to prevent victims from using built-in Windows recovery tools. 
- **Process Termination:** Various database and office services, such as `SQLServer` and `msexchange`, are terminated to ensure files are not in use and skipped during encryption. 
- **File Selection:** Local drives and network shares are the primary targets, but critical system folders (such as `\Windows` and `\Program Files`) and specific extensions (such as `.exe`, `.dll`, and `.sys`) are typically skipped to keep the system functioning.
- **Post-Encryption:** Once all is done, a random 4 to 7 character extension is appended to the encrypted files, the desktop wallpaper is changed to the ransom demand, and in some cases a text to speech voice message alerts the user.

### Indicators of Compromise (IoC)
In order to detect Maze, a mix of host-based artifacts and network-based behaviors are necessary. Even though the group disbanded in 2020, the tactics used and these indicators are highly relevant for identifying successors like Egregor and Sekhmet. These IoCs include:
1. **Host-Based Indicators (Artifacts)**
- **Ransom Notes:** Look for files named `DECRYPT-FILES.txt`, `DECRYPT-FILES.html`, or `MAZE-README.txt` dropped in every encrypted folder. 
- **File Extensions:** Maze typically appends a random 4 to 7 character string (like `.ILnnD`) or a custom extension containing part of the victim ID to encrypted files. 
- **Desktop Background:** The malware often changes the victim wallpaper to an image (such as `111.bmp` in the `%Temp%` folder) displaying the ransom demand. 
- **Malicious Binaries:** Common filenames used in past campaigns include `sss.exe`, `eset.exe`, or random strings like `wupd12.14.tmp`. 
- **Process Termination:** Evidence of security software or database services being forcibly stopped to ensure all files can be encrypted. 
2. **Network-Based Indicators (C2 and Exfiltration)**
- **Data Exfiltration Activity:** Large amounts of outbound traffic to FTP, HTTP, or cloud storage (like Mega.nz) using tools like `WinSCP` or `Rclone`. 
- **Cobalt Strike Artifacts:** Detection of `Cobalt Strike Beacons` communicating with external IP addresses, often disguised using Malleable C2 profiles to look like legitimate traffic. 
- **Unusual RDP Activity:** Frequent failed login attempts or successful RDP sessions from unusual geographic locations, especially outside of business hours. 
- **PowerShell Activity:** Highly obfuscated PowerShell commands used to download payloads or perform internal reconnaissance. 
3. **Behavioral TTPs (Tactics, Techniques, and Procedures)**
- **Shadow Copy Deletion:** Automated use of `vssadmin.exe delete shadows /all /quiet` or `WMIC` commands to destroy local backups. 
- **Administrative Tooling:** Presence of unauthorized reconnaissance tools such as `Adfind`, `BloodHound`, `PingCastle`, or `Mimikatz`. 
- **Security Disabling:** Attempts to disable antivirus or EDR agents through the registry or command line tools prior to the encryption phase. 
4. **Sample File Hashes (SHA-256)**
- `4218214f32f946a02b7a7bebe3059af3dd87bcd130c0469aeb21b58299e2ef9a`
- `9845f553ae868cd3f8d8c3f8684d18f226de005ee6b52ad88b353228b353228b35`
- `c84b2c7ec20dd835ece13d5ae42b30e02a9e67cc13c831ae81d85b49518387b9` 

### Special Features
Maze was a game changer in the world of cybercrime; it introduced and popularized multiple unique features that have become standard in today's RaaS groups. These include:
1. **Core Extortion Innovations** - **Double Extortion:** Maze is credited with pioneering this tactic in late 2019. Beyond just encrypting files, they exfiltrated sensitive data before the lock and threatened to leak it publicly to force payment. 
- **The Maze Cartel:** In mid-2020, Maze formed a collaborative alliance with other ransomware groups like `LockBit` and `RagnarLocker`. They shared their data leak platform and negotiation expertise, creating a unified front against victims. 
- **Data Leak Sites:** They were the first major group to launch a dedicated "name and shame" website on the dark web. This site listed non-paying victims and published samples of their stolen data as proof of the breach. 
2. **Operational and Distribution Models**
- **Affiliate Programs (RaaS):** Maze operated as a Ransomware-as-a-Service model. The core developers provided the malware and negotiation infrastructure, while affiliates carried out the actual intrusions in exchange for a revenue share. 
- **Supply Chain Attacks:** Maze targeted Managed Service Providers (MSPs) like Cognizant. By breaching a single MSP, they could use that provider's access to move into and encrypt the networks of multiple client companies simultaneously. 
- **Manual Lateral Movement:** Unlike worm ransomware, Maze relied on manual lateral movement by human operators using tools like `Cobalt Strike`, `PsExec`, and `Mimikatz` to compromise critical servers before deploying the final payload.

### Real-World Incidents
Maze might have been short-lived, but its lifespan was marked by aggressive high-profile attacks that forced organizations to treat ransomware as a full-scale data breach. Here are some notable incidents:
- **Cognizant (April 2020):** The severe financial impact of this attack makes it stand out as one of the most cited ransomware attacks in history. Across the world, service was disrupted for clients and the company's ability for work-from-home during the pandemic was hindered. Including lost revenue and remediation, Cognizant lost an estimated $50 to $70 million dollars because of this attack. 
- **Canon (August 2020):** Maze operators claimed they had stolen more than 10 terabytes of data from Canon, affecting around 25 different Canon domains. Initially, Canon attributed the outage in its `image.canon` cloud service to technical difficulties; however, it was later confirmed to be a ransomware attack that resulted in the theft of employee personal data.
- **LG Electronics and Xerox (June 2020):** Both LG and Xerox were targeted around the same time, primarily through the exploitation of the `CVE-2019-19781` Citrix vulnerability. 
  - **LG:** The operators bypassed encryption and jumped straight to extortion, leaking 50.2 GB of data that reportedly included source code for firmware projects. 
  - **Xerox:** More than 25 GB of data related to customer support operations was leaked after the company refused to cooperate with the attackers. 
- **City of Pensacola, FL (December 2019):** Maze struck and demanded a $1 million ransom shortly after a high-profile shooting at a local Naval Air Station. The city did not pay the ransom, and the group leaked 2 GB of stolen data as retribution. This caused significant disruption to online payment services for sanitation and energy. 
- **Allied Universal (November 2019):** This incident marked the start of the double extortion era. Once the security firm refused to pay a $2.3 million ransom, Maze leaked 700 MB of stolen data to prove their capability; this represented approximately 10% of the total data exfiltrated.

### Relevant Photos
* [Maze Ransom Note Example 1](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/18_Maze_Ransom_Note.png)
* [Maze Ransom Note Example 2](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/19_Maze_Ransom_Note.webp)

---

## Brain Cipher: 2024
### Overview
Brain Cipher is a ransomware operation that emerged in mid-2024, gaining international notoriety for its high profile attack on Indonesia's National Data Center (PDN). The group utilizes an encryptor based on the leaked LockBit 3.0 (Black) builder, employing a double extortion model where they both encrypt files and threaten to leak stolen data.

#### Origin and discovery
Brain Cipher first emerged as a distinct threat in mid-2024, with its earliest traces discovered by security researchers on June 16, 2024. While most reports date its surfacing to June, research from Group-IB suggests that the individuals behind the operation have been active since at least April 2024. The group is considered a rebranding or a new branch of cybercriminals utilizing the leaked LockBit 3.0 (Black) builder. This allowed them to deploy a sophisticated encryption engine with minor technical modifications, such as the ability to encrypt both file contents and filenames. 

The group's discovery by the global public occurred almost immediately after its first recorded traces due to its massive attack on Indonesia's National Data Center (PDN) on June 20, 2024. This high impact breach paralyzed over 200 government agencies and disrupted international airport operations, turning Brain Cipher into a top tier cybersecurity priority overnight. Researchers have linked the group's infrastructure and ransom note styles to other active threats, suggesting the actors may be the same individuals behind the EstateRansomware and SenSayQ operations.

#### Target industries
Brain Cipher initially gained notoriety through its attacks on government services and has since expanded its operations. It targets a large number of industries, primarily setting its sights on sectors with high public visibility and critical infrastructure. Here is a list of the primary targets: 
- **Government and Public Sector:** This is their most notable target, including national data centers, law enforcement, and municipal systems.
- **Healthcare:** The group frequently targets medical entities and clinics, with recorded hits on providers in the U.S. and France.
- **Manufacturing:** This sector is heavily targeted due to the high impact of production outages, with victims documented in the U.S. and Mexico.
- **Education:** They target both higher education and K-12 institutions, often timing attacks to disrupt critical enrollment periods.
- **Finance and Banking:** Their reach includes financial services and insurance companies in regions like Israel and Ghana.

### Attack Methodology
Brain Cipher utilizes a multi-stage double extortion methodology; this combines advanced encryption with data theft for maximum pressure. It generally occurs in these stages: 
1. **Initial Access and Infiltration:** The group gains entry through several common vectors:
- **Phishing Campaigns:** Sending deceptive emails with malicious links or attachments to trick users into executing the payload.
- **Vulnerability Exploitation:** Targeting unpatched, public-facing applications. Notably, they have exploited `CVE-2023-28252`, a Windows CLFS driver privilege escalation flaw.
- **Insecure Remote Access:** Exploiting weak Remote Desktop Protocol (RDP) setups or using credentials purchased from Initial Access Brokers (IABs). 
2. **Escalation and Evasion:** Once inside, the ransomware establishes persistence and avoids detection by: 
- **Bypassing UAC:** Using legitimate system tools like the Windows Command Shell and the `cmstplua` COM interface to bypass User Account Control (UAC).
- **Disabling Security:** Terminating antivirus processes, disabling Windows Defender by tampering with registry keys, and clearing event logs to hide their tracks.
- **Credential Theft:** Harvesting web session cookies and browser-stored credentials, as well as accessing LSASS to further infiltrate the network. 
3. **Lateral Movement and Data Theft:** The attackers move through the network to map out the environment using tools like `BloodHound` and `Adfind`. They exfiltrate sensitive data to their own servers using tools like `Rclone` before starting the encryption process. 
4. **Encryption and Ransom**
- **Neutralizing Backups:** Before locking files, they delete Volume Shadow Copies using `vssadmin` or `WMIC` and target backup solutions like Veeam to prevent easy recovery.
- **Hybrid Encryption:** Based on the LockBit 3.0 builder, it uses `Salsa20` to encrypt file content and `RSA-1024` to secure the keys.
- **Unique Indicators:** It renames files with a random alphanumeric extension (such as `.sYMY1N6ah`) and places a ransom note in the format `<extension>.README.txt` in every compromised folder.

#### Initial Access Techniques
There are a few distinct methods that Brain Cipher uses for initial access; this is usually done through leveraging automated exploits and social engineering. These methods include:
- **Phishing Campaigns:** This is a primary entry vector where the group sends deceptive emails containing malicious links or attachments. These are designed to trick employees into downloading and executing files that launch the initial infection stage. 
- **Exploitation of Public-Facing Applications:** They target vulnerabilities in internet-facing software to gain a foothold. A notable example is the exploitation of `CVE-2023-28252`, a high-severity privilege escalation flaw in the Windows Common Log File System (CLFS) Driver. 
- **Compromised Remote Access:** The group frequently exploits insecure Remote Desktop Protocol (RDP) setups or Virtual Private Networks (VPNs). They may use brute-force attacks to guess passwords or leverage credentials previously stolen through other means. 
- **Initial Access Brokers (IABs):** Brain Cipher is known to purchase pre-established access from specialized third party brokers on the dark web. These brokers perform the initial breach and then sell the verified network access to ransomware operators, allowing them to move directly to data exfiltration. 
- **Credential Harvesting:** Before full-scale encryption, they often steal web session cookies and browser-stored passwords. This allows them to bypass authentication and move deeper into the network using legitimate user accounts.

#### Lateral Movement
Once inside, Brain Cipher uses a mix of Living-off-the-Land (LotL) techniques and specialized malware to navigate the network. Before they begin moving, the attackers perform reconnaissance and discovery. Some common commands they use to do so include:
- `net view /all` (Sees all shared resources)
- `nltest /domain_trusts` (Maps out the network trust structure)
- `whoami /all` (Checks their current privilege level)

Otherwise, once they have got a lay of the land, their lateral movement techniques include:
- **Credential Harvesting:** They use tools like `Mimikatz` or `LaZagne` to dump passwords and hashes from memory. This allows them to perform pass-the-hash attacks or use legitimate admin credentials to log into other machines without raising red flags.
- **Remote Management Tools:** They heavily rely on built-in Windows tools like `PsExec`, `PowerShell`, and `WMI` (Windows Management Instrumentation). These allow them to execute commands and deploy the ransomware payload onto remote workstations and servers across the entire domain.
- **Network Scanning:** To find critical assets, they use scanners like `Advanced IP Scanner` or `NetScan` to map out the network topology and identify high-value targets like backup servers and databases.
- **Exploiting Vulnerabilities:** They often look for internal unpatched systems. For example, they utilize `CVE-2023-28252` (a Windows CLFS flaw) not just for initial entry, but to escalate privileges to `SYSTEM` level once they are inside a sub-network.
- **Command and Control (C2) Frameworks:** They frequently use `Cobalt Strike` beacons. This provides them with persistent, interactive remote control over compromised machines, making it easy to hop between different departments or segments.

#### Encryption Process
Borrowing heavily from the leaked LockBit 3.0 (Black) builder, Brain Cipher's encryption process is highly efficient and difficult to reverse without the attacker's private key. Some key aspects include: 
1. **Encryption Algorithms:** The group uses a hybrid encryption scheme to balance speed with security: 
- **File Encryption:** It uses the `Salsa20` stream cipher to lock the actual file content. 
- **Key Protection:** The symmetric key used for the files is then encrypted using `RSA-1024`, ensuring only the attackers can unlock it. 
2. **Performance Optimization:** To paralyze large systems quickly, Brain Cipher often employs partial encryption: 
- **Strategic Corruption:** Instead of encrypting every byte of a large file, it typically only encrypts the first 512 KB (offset `0x80000`). 
- **Impact:** Since this initial block usually contains critical headers and metadata (like those in `.mp3`, `.pdf`, or `.docx` files), the file becomes unreadable even though most of its raw data remains untouched. 
- **Exceptions:** Smaller files under 512 KB are fully encrypted. 
3. **File Transformation:** Once a file is encrypted, the ransomware performs several visible changes: 
- **Filename Scrambling:** Unlike many variants that only add an extension, Brain Cipher often encrypts the original filename itself, replacing it with a random string. 
- **Random Extensions:** It appends a unique, randomized extension to every file based on a hash generated during execution (e.g., `.sYMY1N6ah`). 
- **Ransom Notes:** A note titled `[extension].README.txt` is dropped in every folder, containing the victim's unique encryption ID and contact instructions. 
4. **Preparation and Anti-Recovery:** Before the encryption begins, the malware executes several "clean-up" steps through direct API calls to avoid detection: 
- **Service Termination:** It kills processes related to databases (SQL), virtual machines (Hyper-V, VMware), and backup software (Veeam) to ensure it can gain a file lock. 
- **Backup Deletion:** It specifically targets and deletes Volume Shadow Copies and system restore points. It has been observed deleting the VSS registry key `HKLM\System\CurrentControlSet\Services\VSS` to permanently disable the service.

### Indicators of Compromise (IoC)
Due to the fact that the group uses the LockBit 3.0 (Black) builder, many technical artifacts are identical to that strain. Some key IoCs include:
1. **File and Hash Indicators**
- **Malicious Hashes:** `eb82946fa0de261e92f8f60aa878c9fef9ebb34fdababa66995403b110118b12` (Common binary hash)
- **Encrypted File Pattern:** Files are renamed to a specific format: `<random alphanumeric characters>.<9 random alphanumeric characters>` (such as `a1b2c3d.e4f5g6h7i`). 
- **Ransom Notes:** `[9-character-extension].README.txt`
2. **Network and Communication**
- **Email Aliases:** `brain.support@cyberfear.com`, `qn.support@cyberfear.com`, `brain.dataleak@cyberfear.com`
- **Tor Infrastructure:**
  - **Victim Portal:** `http://mybmtbgd7aprdnw2ekxht5qap5daam2wch25coqerrq2zdioanob34ad.onion`
  - **Data Leak Site:** `http://vkvsgl7lhipjirmz6j5ubp3w3bwvxgcdbpi3fsbqngfynetqtw4w5hyd.onion`
- **Tox ID:** `BEBA1CBBD4C1D6DFCB788024174FDE6AE6137C7835FBF997CB178DB5697AE574FB6055381095`
3. **Host-Based Artifacts**
- **UAC Bypass:** Evidence of `dllhost.exe` launching with a specific CLSID for the `cmstplua` COM interface. 
- **Registry Tampering:** Modification of the `ChannelAccess` and `Enabled` keys within Windows Event Log channels to hide activity. 
- **Process Activity:** Unauthorized access to `LSASS` (Local Security Authority Subsystem Service) by the ransomware executable for credential dumping. 
4. **Behavior-Based Red Flags**
- **Partial Encryption:** Files only encrypted up to the first 512 KB (offset `0x80000`). 
- **Unauthorized Tools:** Presence of tools like `Mimikatz`, `LaZagne`, `Advanced IP Scanner`, or `PsExec`.

### Special Features
Brain Cipher uses a sophisticated set of features typical of modern high tier ransomware operations, heavily influenced by LockBit 3.0 (Black). Some of these include:
1. **Core Extortion Features**
- **Double Extortion:** This is their standard operating model. They first exfiltrate sensitive data and then encrypt the victim files. Victims are pressured to pay twice: once for the decryption key and again to prevent the public release of their stolen data. 
- **The "Mercy" Pivot:** Unique to the Indonesia National Data Center attack, Brain Cipher demonstrated a rare PR focused move by issuing a public apology and releasing a free decryptor. This was framed as a lesson to the government regarding its security posture rather than a failed extortion attempt. 
- **Data Leak Sites (DLS):** The group operates a dedicated Tor-based leak site to name and shame non-paying victims. The platform includes countdown clocks and file samples to prove the validity of the breach, a tactic designed to maximize psychological pressure. 
2. **Operational Model**
- **Ransomware-as-a-Service (RaaS):** Brain Cipher operates as a RaaS model, where core developers provide the malware and infrastructure to affiliates. They use the leaked LockBit 3.0 (Black) builder, allowing them to quickly onboard affiliates who carry out the actual intrusions and share the resulting profits. 
- **Vulnerability Focus:** The group leans heavily on exploiting specific flaws for elevation and persistence. They are known for utilizing `CVE-2023-28252` to gain `SYSTEM` privileges and have been observed using Image File Execution Options (IFEO) injection to maintain a foothold in high value environments. 
3. **Propagation and Movement**
- **Manual Lateral Movement:** The ransomware does not "worm" automatically. Instead, it relies on human operators once they have gained high level credentials. They use tools like `PsExec` and `PowerShell` to push the ransomware to every machine on the network simultaneously after mapping the environment with `BloodHound` or `Adfind`. 

### Real-World Incidents
Brain Cipher's high impact attacks on government infrastructure and large professional services firms have marked its reputation. Some of these incidents include:
- **Indonesia National Data Center (June 2024):** This remains the group's most famous attack, where they paralyzed the Temporary National Data Center (PDNS), disrupting over 200 government agencies. The breach severely impacted immigration services at major airports and online student registration systems. 
  - **The Ransom:** They initially demanded $8 million in cryptocurrency. 
  - **The Outcome:** On July 2, 2024, the group released the decryption key for free and issued a public apology, claiming the attack was a demonstration of security flaws in the national infrastructure. 
- **Rhode Island RIBridges Platform (December 2024):** In a massive breach, Brain Cipher targeted the RIBridges system, which manages state social services like Medicaid and SNAP. 
  - **Impact:** The group exfiltrated data from 28 systems, compromising the personal information of over 650,000 individuals, including Social Security numbers and health data. 
  - **The Breach:** Investigation revealed that the actors gained access in July 2024 via a RIBridges VPN using stolen credentials from a Deloitte employee, remaining undetected for five months. 
- **Deloitte UK (December 2024):** The group claimed to have exfiltrated 1 TB of compressed data from Deloitte UK and posted the firm on their leak site. 
  - **The Response:** Deloitte stated that the incident was limited to a single client system sitting outside the main Deloitte network. No internal Deloitte systems were impacted, according to their official investigation. 
- **International Targets:** The group's leak site has featured a diverse range of victims, including the Pulmonary Physicians of South Florida, Estar Seguros in Venezuela, and multiple manufacturing entities across North and South America.)

### Relevant Photos
* [Brain Cipher Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/20_Brain_Cipher_Ransom_Note.png)
* [Brain Cipher Alternative Ransom Note](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/21_Brain_Cipher_Ransom_Note_Alt.png)
* [Brain Cipher Data Recovery Portal](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/22_Brain_Cipher_Data_Recovery_Site.png)
* [Brain Cipher Negotiator Chat Room](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/23_Brain_Cipher_Chat_Room.png)
* [Brain Cipher Attack Announcement](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/24_Brain_Cipher_Attack_Announcement.png)
* [Brain Cipher Data Leak Sample](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Five/Ransomware%20Timeline/25_Brain_Cipher_Data_Leak.png)
