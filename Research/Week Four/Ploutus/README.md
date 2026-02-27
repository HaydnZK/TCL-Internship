# FBI Alert: Ploutus Malware Drains US ATMs without a Card or Account

## What's Happening
Between February 19 and 20, 2026, an emergency flash alert from the Federal Bureau of Investigation (US law enforcement agency) described a surge in ATM jackpotting attacks across the United States. The Ploutus family of malware forces ATMs to dispense cash without requiring a card, PIN, or account authentication. Reports indicate more than $20 million in losses in 2025 across over 700 incidents and nearly 1,900 incidents since 2020, with some estimates exceeding $40 million in total damages. This threat demonstrates the convergence of physical and digital security risks within financial infrastructure.

### Details from the Alert
The malware exploits the eXtensions for Financial Services (XFS) middleware layer, an industry standard for controlling ATM hardware. By abusing this interface, the malware can issue hardware commands across different ATM vendors with minimal configuration. The FBI alert notes that organized criminal groups, including individuals linked to the Tren de Aragua (venezuelan gang), have been indicted in connection with these attacks. This emphasizes that ATM jackpotting is not opportunistic but coordinated and financially motivated.

---

## What is XFS
eXtensions for Financial Services (XFS) is an industry standard middleware layer that enables ATM software to communicate with hardware components such as cash dispensers and card readers. The interface provides vendor independence, allowing software to operate across different ATM manufacturers. However, XFS often lacks authentication for hardware commands, creating an opportunity for malicious software to issue dispensing instructions and bypass normal financial controls.

### Why is XFS Targeted
XFS offers functionality but also presents risks that make it attractive to attackers:
- No Authentication: Many XFS implementations do not require strong authorization for hardware commands, allowing unauthorized software to interact with ATM components.
- Universal Hardware Control: The vendor-independent design means malware written for XFS can operate across diverse ATM models.
- Physical and Digital Blend: XFS enables jackpotting by allowing software to directly control dispensing hardware.
- Data Hiding: Certain XFS file system configurations can be abused for anti-forensic purposes, making malicious activity harder to detect.

---

## What is Ploutus
Ploutus is a family of malware designed to target ATMs through jackpotting attacks. While technically sophisticated, its operational model is straightforward. Variants such as Ploutus-D target specific ATM models, including Diebold Nixdorf systems, and were widely observed in 2017. Early versions of the malware included a Spanish language interface, indicating initial targeting in Latin American markets. Ploutus also attempts to delete logs and evidence to evade detection and can establish persistence by modifying registry entries to survive system reboots.

### How the Attack Works
The attack uses a combination of physical access and malware installation:
1. The attacker gains physical access to the ATM’s internal components, often by opening the upper cabinet using generic keys.
2. The attacker installs Ploutus by replacing the ATM’s hard drive with an infected drive or connecting an external device such as a USB drive or laptop.
3. After installation, the malware communicates directly with dispensing hardware and bypasses financial authorization systems. External keyboard commands may trigger the jackpot function.
4. The ATM dispenses cash within minutes, resulting in immediate financial loss.

---

## MITRE Techniques
Ploutus leverages multiple techniques mapped by the MITRE ATT&CK framework:
- Initial Access (Physical Access: T1205): Physical compromise of the ATM’s internal system.
- Execution (Command-Line Interface: T1059): Commands issued through ATM interfaces and function key sequences.
- Persistence (Boot or Logon Autostart Execution: T1547): Registry modifications that enable the malware to survive reboots.
- Defense Evasion (Obfuscation and Packing: T1027): Techniques such as string encryption and control-flow obfuscation that slow forensic analysis.
- Impact (Data Destruction and Manipulation: T1485): The primary goal of cash dispensing and financial disruption.

---

##Indicators of Compromise
Files associated with Ploutus include:
- Newage.exe
- Color.exe
- Levantaito.exe
- WinMonitor.exe (multiple variants)
- C.dat
- P.bin (containing MAC addresses and the string "PLOUTUS-MADE-IN-LATIN-AMERICA-XD")

### Additional indicators:
- Registry Key: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
- Value: Diebold.exe,%system32%/userinit.exe
- Service Name: DIEBOLDP
- Mutexes: Ploutos, DIEBOLDPL, KaligniteAPP
- Path: C:\Diebold\EDC\edclocal.dat

### Behavioral indicators:
- Unauthorized remote access tools such as TeamViewer or AnyDesk
- Unexpected USB insertion events
- Evidence of physical tampering with the ATM’s upper cabinet
- Unusual .NET service activity

### MD5 hashes associated with malicious files:
- C04A7CB926CCBF829D0A36A91EBF91BD
- 5AF1F92832378772A7E3B07A0CAD4FC5

Indicators should be validated in operational context because malware variants evolve and filenames alone are insufficient for detection. Hashes should be cross-referenced with trusted sources before use in production environments.

---

## ISO/IEC 27001 Annex A Controls Present in Analysis

- **A.5 Information Security Policies**
  Policies and governance concepts are addressed through security recommendations and layered control strategies.
- **A.7 Human Resource Security**
  Awareness of operational and insider risks is implied by controls addressing physical access and operational security.
- **A.8 Asset Management**  
  Critical ATM components and financial systems are identified as assets requiring protection and proper handling.
- **A.9 Access Control**  
  Least privilege principles and restrictions on unauthorized access are central to preventing hardware and software abuse.
- **A.11 Physical and Environmental Security**  
  Physical security controls are necessary because ATM attacks require direct access to internal hardware.
- **A.12 Operations Security**  
  Malware prevention, change management, and operational safeguards are addressed through recommendations and analysis.
- **A.13 Communications Security**  
  Although the attack focuses on hardware, secure communications and data integrity remain relevant to financial operations.
- **A.14 System Acquisition, Development, and Maintenance**  
  Secure system design and software integrity concepts support resistance to malware and unauthorized modifications.
- **A.16 Information Security Incident Management**  
  Detection, response, and analysis of security incidents align with SOC and incident management principles.
- **A.17 Information Security Aspects of Business Continuity**  
  Financial systems require resilience and continuity planning to maintain secure operations during disruptions.
- **A.18 Compliance**  
  Financial infrastructure must adhere to regulatory and security obligations, reinforcing the need for governance and controls.

---

## Defenses Against Ploutus
Preventive controls recommended by the FBI and security best practices include:
- Secure Physical Access: Replace standard keys with higher-security locks to restrict access to internal components.
- Monitor for Tampering: Deploy vibration and temperature sensors and maintain camera coverage of sensitive areas.
- Network Security: Encrypt hard drives, verify software integrity through gold image checks, and restrict the use of removable media.
- Monitor for Offline Status: Investigate machines that go out of service unexpectedly or report low cash without transactions.

Layered security combining physical controls, monitoring, and software integrity checks reduces risk by addressing both physical and digital attack vectors.
