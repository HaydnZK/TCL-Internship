# Access Token Manipulation (T1134)
## Description
Access Token Manipulation happens when a threat actor modifies access tokens in order to operate as a different user or system security context, enabling them to perform actions and bypass access controls. Windows utilizes access tokens to determine the owner of an active process. Threat actors can force these tokens to make running processes appear as if they're the child of a different process, or that they belong to someone other than the original owner. This causes the process to take on the security context associated with the new token.

Built-in Windows API functions can be abused by threat actors to copy access tokens for existing processes, also known as token stealing. The stolen tokens can be applied to existing processes (Token Impersonation/Theft: T1134.001) or used to create a new process (Create Process with Token: T1134.002). To achieve this, a threat actor usually must be a privileged user, such as an administrator. Token stealing is often used to elevate privileges from Administrator to SYSTEM level. Afterward, access tokens can be used to authenticate to remote systems under the account for that token, assuming the account has appropriate permissions.

Standard users can also use the `runas` command or relevant Windows API functions to create impersonation tokens. Other methods, including abusing Active Directory (AD) fields, can modify access tokens.

These attacks generally aim to achieve one of two objectives: either escalate privileges or move laterally, though they are more frequently associated with privilege escalation.

## Token Types (in the context of T1134)
There are two main types of tokens involved in this technique:
- **Primary Tokens:** Associated with a process and define the security context for that process.  
- **Impersonation Tokens:** Applied at the thread level, allowing operations under a different security context, generally a user’s, rather than the original process’s primary token.

### Token-Related Attributes
When T1134 discusses security contexts, it generally refers to:
- **SYSTEM Tokens:** High-privileged tokens often targeted to gain full system control.  
- **NETONLY Tokens:** Usually generated during `runas` and `/netonly` scenarios, allowing access to resources on a network requiring different credentials.

### What's in a Windows Access Token
A Windows access token typically contains:
- User SID (Security Identifier)  
- Group SIDs  
- Privileges (e.g., SeDebugPrivilege, SeImpersonatePrivilege)  
- Default DACL (Discretionary Access Control List)  
- Integrity level  
- Logon Session ID (LUID)  
- Token type (primary vs. impersonation)

## Sub-Techniques
There are several sub-techniques for Access Token Manipulation:
- **T1134.001 - Token Impersonation/Theft:** Stealing a token from another process to gain higher privileges (e.g., `DuplicateTokenEx`, `ImpersonateLoggedOnUser`).  
- **T1134.002 - Create Process with Token:** Launching a new process using a stolen or duplicated token (e.g., `CreateProcessWithTokenW`, `runas`).  
- **T1134.003 - Make and Impersonate Token:** Creating a new token from scratch using stolen credentials (e.g., `LogonUser`).  
- **T1134.004 - Parent PID Spoofing:** Creating a process and making it appear as the child of a different process to hide malicious activity.  
- **T1134.005 - SID-History Injection:** Injecting security identifiers into a token to gain unauthorized access to network resources.

## The Process
The attacker gains a foothold, such as through a spear-phishing email. They now have a shell running under the compromised user’s security context. This may involve spawning new processes or directly injecting into memory. The attacker's code operates with an access token that belongs to the compromised user, allowing them to bypass local access checks or authenticate remotely.

Attackers typically want to move laterally quickly, which can be done in three ways. Each option depends on the relationship between access tokens, logon sessions, and cached credentials. Tokens provide access within the logon session, which can also expose cached credentials.

For lateral movement via Windows SSO, attackers must maintain these links: a handle to the token linked to a logon session backed by target credentials. Without this, movement is limited to creating new logon sessions or modifying existing ones (cached credentials or token-logon session links).

### Lateral Movement Options
1. **Steal the token of an already logged-on privileged user (non-network logon):**  
If another privileged user is logged in, the attacker can obtain a handle to their access token. Whether impersonating the token or starting a new process, if the token is linked to a non-network logon session, cached credentials are available. This allows authentication to other hosts across the network using Windows SSO, pivoting without dumping credentials.

2. **Create a new logon session using stolen credentials and impersonate the returned token or spawn a new process:**  
When no privileged user is logged on, the attacker can find credentials elsewhere to create a new logon session. Windows caches certain logon types, so a new token backed by stolen credentials can be obtained. This token allows authentication off the host via Windows SSO. Credentials may be obtained via Kerberoasting or searching accessible resources like network shares, SharePoint, internal wikis, enterprise GitHub, Zendesk, etc.

3. **Change cached credentials associated with the current access token:**  
Instead of creating a new logon session, the attacker modifies cached credentials linked to the current token and logon session. Windows Security Support Providers (SSPs) may provide native methods that do not require elevated privileges.  
Alternatively, attackers can manually modify cached credentials in LSASS. This requires elevated privileges to obtain a write handle (PROCESS_VM_WRITE) to LSASS via OpenProcess, commonly used in pass-the-hash attacks.

**LSASS:** The Local Security Authority Subsystem Service (lsass.exe) manages authentication, enforces security policies, handles password changes, and generates access tokens. It is also a prime target because it stores sensitive credentials in memory, which attackers can leverage for lateral movement.

## Real-World Context
Several threat groups have used Access Token Manipulation:

### Qilin Ransomware
Used Mimikatz to steal tokens from processes like `lsass.exe`, `winlogon.exe`, or `wininit.exe` to escalate to `NT AUTHORITY\SYSTEM`.

### Blue Mockingbird
Abused SeImpersonate token privileges via the JuicyPotato exploit to escalate from web app pool accounts to `NT AUTHORITY\SYSTEM`.

### APT41
Used BADPOTATO exploit, obfuscated by ConfuserEx, to escalate to `NT AUTHORITY\SYSTEM` from named-pipe impersonation.

### Cuba Ransomware
Used `SeDebugPrivilege` and `AdjustTokenPrivileges` for privilege escalation within compromised systems.

### Ghost (Cring) Ransomware
Targeted internet-facing services since 2021, using multiple techniques to escalate privileges for ransomware deployment.

## Detection and Mitigation
### Detection
Detecting T1134 involves monitoring for unauthorized privilege escalation. Watch for user processes spawning as `SYSTEM` or illicit use of `runas`.

**Strategies:**
- **Monitor API Calls:** Look for anomalous usage of `DuplicateToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `SetThreadToken`.  
- **Process Lineage Analysis:** Identify suspicious parent-child process relationships, such as user-level processes spawning SYSTEM-level processes.  
- **Command-Line Auditing:** Watch for unusual use of tools like `runas`.  
- **Event Tracing for Windows (ETW):** Analyze ETW data for token manipulation and PPID spoofing.

### Mitigation
Enforce least privilege, use Privileged Access Management (PAM) solutions, monitor token-related APIs, and apply patches to prevent credential theft.

**Strategies:**
- **Principle of Least Privilege:** Limit user permissions and avoid unnecessary administrator rights.  
- **Privileged Access Management (PAM):** Implement PAM or Just-In-Time (JIT) access to secure privileged credentials.  
- **Token Protection:** Use OS security features to prevent token theft and manipulation.  
- **System Hardening:** Apply security patches to OS and applications to prevent exploitation.  
- **Behavioral Monitoring:** Use Endpoint Detection and Response (EDR) to detect unauthorized access or abnormal token use.
