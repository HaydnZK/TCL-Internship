# DomainSleuth
## Vulnerability Research & Logic Mapping
This phase involves identifying the specific Active Directory misconfigurations our system will detect. By defining the technical flags and security risks now, we create a blueprint for the coding phase and ensure the output is actionable for a blue team environment.

| Vulnerability | MITRE ATT&CK Mapping | ISO 27001:2022 Annex A |
|--------------|-----------------------------|----------------------------|
| Excessive Rights/ACLs | T1098: Account Manipulation | A.9.2: User access provision |
| Insecure Delegation | T1558: Steal or Forge Kerberos Tickets | A.9.4: System and application access control
| AS-REP Roasting | T1558.004: AS-REP Roasting | A.9.3: User responsibilities (Password Policy) | 
| Machine Account Quota | T1098: Account Manipulation | A.12.1: Operational procedures/responsibilities |
| Outdated OS | T1190: Exploit Public-Facing App | A.12.6: Tech vulnerability management |

### Vulnerability 1: Excessive User Rights and Permissions 
This involves allowing unprivileged users to make sensitive changes, including Group Policy Object (GPO) modifications and changing ownership of objects (ACL abuse). 

#### **Technical Logic**
When attempting to identify excessive user rights and permissions with SharpHound outputs, the key is to look for specific ACE flags and Edge properties that can reveal these flaws. The keys to finding this vulnerability lies in: 
1. **Primary ACE Flags**: Some of the specific values to look for in ACEs or Edge sections of SharpHound JSON files include:
- **GenericAll**: This is the biggest red flag. This grants full control over an object, which allows a user to do things like change passwords, modify attributes, and take over groups or computers entirely. 
- **GenericWrite**: This can allow a user to update any non-protected attribute of an object. This is frequently abused for the modification of things like `servicePrincipalName` for Kerberoasting. 
- **WriteDacl**: This gives the ability to modify permissions of an object. Users that have this property can grant themselves `GenericAll` at anytime. 
- **WriteOwner**: This gives the ability for a user to take ownership of an object. Once someone owns it, they can overwrite the DACL to grant themselves full control. 
- **AllExtendedRights**: This includes high-privileged tasks, such as resetting passwords and performing a DCSync attack if granted at domain level. 

2. **Specific Rights for Lateral Movement**: There are specific rights that show what a user can do on a domain system, this is a common area for excessive permissions, these include: 
- **AdminTo**: This Edge is used t o identify users who have local admin rights on a remote system. 
- **CanRDP**: This specifically identifies users who have the right to login through RDP. 
- **SeRemoteInteractiveLogonRight**: In the raw SharpHound collection, this User Right Assignment (URA) is what has the power to enable the `CanRDP` edge. 
- **CanPSRemote**: This identifies which users have the permission to execute commands through PowerShell Remoting. 

3. **Hidden Relationships**: Looking for these properties can help identify unintended control, these include:
- **AddMember**: This is frequently found in Group Objects and permits users to add anyone to the group. This effectively inherits all of that group's permissions. 
- **ForceChangePassword**: This explicitly allows a user to reset the password of another user without knowing the previous one. 

#### **The Parser**
```python
def check_excessive_permissions(users, flags):

    dangerous_rights = [
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "AllExtendedRights"
    ]

    for user in users:

        properties = user.get("Properties", {})
        username = properties.get("name", "UnknownUser")

        aces = user.get("Aces", [])

        # Use a SET to prevent duplicates
        found_rights = set()

        for ace in aces:

            right = ace.get("RightName")

            if right in dangerous_rights:
                found_rights.add(right)

        # Only add a flag if something dangerous was found
        if found_rights:

            flags.append({
                "user": username,
                "vulnerability": "Excessive Permissions",
                "permissions": list(found_rights),
                "description": f"{username} has dangerous rights: {', '.join(found_rights)}"
            })

```

#### **Security Risk**
Excessive user rights and permissions in Active Directory (AD) create critical security risks, primarily by facilitating privilege escalation, lateral movement by attackers, and increasing the impact of insider threats. Too many privileged accounts (like Domain Admins) or over-privileged users provide attackers with "keys to the kingdom," allowing them to steal credentials, deploy malware, and exfiltrate data while bypassing detection. 
- **Rapid Privilege Escalation & Lateral Movement**: Attackers who compromise a standard account with excessive privileges can quickly escalate to full domain control, often by leveraging misconfigured group memberships, such as nesting.
- **Increased Attack Surface**: More privileged accounts mean more targets. Attackers target "hidden" high-privilege accounts, including inactive or service accounts with, for example, "Debug programs" rights, allowing them to take over system-level processes.
- **Insider Threats & Malicious Activity**: Employees with more access than required can easily cause intentional or unintentional damage. Disgruntled employees can abuse their privileges for data theft, fraud, or sabotage.
- **Failed Compliance & Audit Violations**: Excessive, undocumented, or unreviewed permissions violate regulatory compliance standards, leading to financial penalties and audit failures.
- **Uncontrolled Privilege Creep**: Over time, employees accumulate rights, and failing to remove these permissions when roles change (privilege creep) leaves unnecessary, dangerous access paths open.
- **Data Breach & Lateral Movement**: Attackers moving through the network can use over-privileged service accounts (which often lack password rotation or MFA) to access, modify, or delete sensitive data. 

#### **Mitigation**
Mitigating excessive user rights in Active Directory (AD) involves implementing the principle of least privilege, restricting membership in privileged groups (Domain Admins, Enterprise Admins), and utilizing delegated administration. Key actions include using LAPS for local passwords, removing users from local administrator groups, adopting Privileged Access Management (PAM), and conducting regular audits to remove unused accounts and permissions. 
1. **Key Mitigation Strategies**
- **Enforce Least Privilege**: Ensure users have only the minimum permissions necessary to perform their job functions, preventing "privilege creep".
- **Protect High-Privilege Groups**: Strictly limit and audit members of built-in privileged groups like Domain Admins, Enterprise Admins, and Schema Admins.
- **Implement Tiered Administration**: Use separate, hardened accounts for administrative tasks, ensuring they are not used for daily activities like email or web browsing.
- **Use Delegation of Control**: Instead of granting high-level rights, use the Active Directory Delegation of Control Wizard to assign specific, limited permissions (e.g., password resets) to specific Organization Units (OUs).
- **Secure Service Accounts**: Implement Group Managed Service Accounts (gMSAs) to automate password management, reducing the risk of compromised service accounts.
- **Remove Unused Accounts**: Regularly audit for inactive, disabled, or stale user and computer accounts (e.g., no login in 90 days) and delete them.
- **Monitor for Over-Privileged Accounts**: Audit permissions, particularly for sensitive groups and objects, to identify and rectify excessive rights.
- **Utilize Restricted Groups**: Use Group Policy Restricted Groups to manage membership of critical groups, ensuring unauthorized users are automatically removed. 

2. **Operational Best Practices**
- **Audit and Log**: Enable detailed auditing (AD DS events 3044-3056) to monitor for malicious or unauthorized changes, particularly following Microsoft security updates.
- **Use LAPS**: Implement the Local Administrator Password Solution (LAPS) to automatically manage and randomize local administrator passwords on computers, preventing lateral movement.
- **Limit Helpdesk Rights**: Create specific OUs for helpdesk staff to limit their scope of control to specific user groups, preventing them from modifying higher-level privileged accounts.
- **Monitor DCSync/DCShadow**: Protect against attacks that exploit AD replication rights, such as DCSync, by monitoring for unauthorized users with `DS-Replication-Get-Changes` rights.


### Vulnerability 2: Insecure Delegation
Through the use of unconstrained delegation, services can impersonate users on any machine in the network. This can allow an attacker to simply wait for an admin to log in and become that admin. 

#### **Technical Logic**
Identifying insecure delegation vulnerabilities relies on looking for specific Boolean properties as well as edge relationships in JSON files. There are three main types of categories that SharpHound delegates to, each with its own flag or data point. These include: 
1. **Unconstrained Delegation**: This is the most critical because the server can impersonate any user who authenticates to it and can forward credentials somewhere else. What to look for: 
- **JSON Property**: Finding `"unconstraineddelegation": true` in the `Properties` block of Computer and User objects. 
- **Logic**: Any system that's not a DC with this flag set is an attractive target because threat actors can harvest TGTs from privileged users who connect to it. 

2. **Constrained Delegation (Traditional)**: This limits impersonation to specific services but is still capable of being abused if a user has control over the service account. 
- **JSON Edge**: Here, we want to find the `AllowedToDelegate` edge. 
- **JSON Property**: In older or raw data, look at the `msds-allowedtodelegateto` attribute to list the SPNs an account is allowed to impersonate user rights. 
- **Vulnerability**: If a non-admin user has `GenericWrite` or `GenericAll` over an account with `AllowedToDelegate`, it's possible they can escalate to the services listed in that attribute. 

3. **Resource-Based Constrained Delegation (RBCD)**: This is the modern version where target resources (such as a computer) defines who can delegate to it. What to look for: 
- **JSON Edge**: Here, we want to find the `AllowedToAct` edge. 
- **Target Attributes**: This maps to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the target computer object. 
- **Vulnerability**: If a user has write permissions (such as `GenericWrite`, `WriteDacl`, etc) over a computer object, they're able to set this attribute to their own account, which essentially grants themselves admin access to the machine. 

#### **The Parser**
```python
def check_unconstrained_delegation(users, flags):

    for user in users:

        properties = user.get("Properties", {})

        username = properties.get("name", "UnknownUser")

        if properties.get("unconstraineddelegation") == True:

            flags.append({
                "user": username,
                "vulnerability": "Unconstrained Delegation",
                "description": f"{username} has unconstrained delegation enabled (high risk)."
            })

```

#### **Security Risk**
Insecure delegation, specifically unconstrained delegation in Active Directory (AD), allows a service or computer to impersonate any user to any other service in the domain. If an attacker compromises a server with this setting, they can steal user Ticket-Granting Tickets (TGTs) from memory, enabling full domain compromise, lateral movement, and privilege escalation.
- **Full Domain Compromise**: Attackers can extract cached TGTs (e.g., via Mimikatz) from a compromised service account or machine, allowing them to impersonate any user, including Domain Admins.
- **Lateral Movement**: Attackers can move freely between systems without needing to steal user passwords, as they can impersonate users who authenticate to the compromised service.
- **Persistence**: By impersonating privileged users, attackers can create persistent access that is difficult to detect.
- **Printer Bug Exploitation**: Attackers can force domain controllers (DCs) to authenticate to a compromised, unconstrained machine, grabbing the DC’s ticket and gaining control of the entire domain.
- **Targeting Machine Accounts**: Insecure delegation applies to computer accounts, not just users. A compromised machine with unconstrained delegation can impersonate other sensitive machine accounts, which often hold domain admin privileges. 

#### **Mitigation**
Insecure delegation in Active Directory (AD), specifically unconstrained delegation, allows a service to impersonate users to any other service, posing a massive privilege escalation risk. Mitigation involves identifying and removing this setting, enforcing constrained delegation, protecting high-privileged accounts, and disabling unnecessary services like Print Spooler. 
1. Core Mitigation Steps
Identify Vulnerable Objects: Use PowerShell to find computer objects with TrustedForDelegation set to true.
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}.
Disable Unconstrained Delegation: Change the setting from "Trusted for delegation" to "Do not trust this computer for delegation" in Active Directory Users and Computers (ADUC).
Implement Constrained Delegation: If services require delegation, use Resource-Based Constrained Delegation (RBCD) to restrict what services a computer can impersonate.
Protect Privileged Accounts: Set the attribute "Account is sensitive and cannot be delegated" on all high-privileged accounts (Domain Admins, Service Accounts) to prevent them from being impersonated.
Use Protected Users Group: Add high-privileged users to the Protected Users Security Group (Windows Server 2012 R2+), which restricts how credentials are cached.

2. Threat Mitigation
Block Coercion Attacks: Disable the Print Spooler service on domain controllers to prevent attackers from forcing the DC to authenticate to a compromised, unconstrained server.
Audit Permissions: Regularly audit who has the right to enable delegation, as this right can be abused to gain domain control. 

3. Summary Table of Delegation Types
| Delegation Type | Security Level | Risk |
| Unconstrained	Insecure (Legacy) | High: Attacker can impersonate any user to any service. | 
| Constrained | Secure | Medium: Limits delegation to specific services. | 
| Resource-Based | Most Secure | Low: Hardest to abuse; defines access at the target. | 

### Vulnerability 3: Weak Password Policies (AS-REP Roasting)
Allowing the use of weak passwords that are simple or short. In this specific scan, we look for accounts that don't require Kerberos pre-authentication, making them easy targets for offline cracking.

#### **Technical Logic**
Finding AS-REP Roasting in SharpHound's output involves finding specific properties that flag accounts with Kerberos pre-authentication disabled. Things to note are:
1. **The JSON Property for AS-REP Roasting**: In the SharpHound `users.json` file, looking for this exact key-value pair in the `Properties` block of each user object: 
- **Property**: `"dontreqpreauth": true`
- **Logic**: If this is set to `true`, this means that the `DONT-REQ-PREAUTH` flag is set in the `userAccountControl` attribute of the user. 

2. **How to Use in a Script**: When attempting to parse JSON, the script should flag any user where the property is present and set to true. 
- **Vulnerability Indicator**: An attacker with this property has the ability to request Kerberos tickets for these users without needing a password. The response (AS-REP) holds data encrypted with the user's password hash, which can be cracked offline. 

3. **Why These are Vulnerable**: There are a few reasons why these accounts are vulnerable, including: 
- **No Authentication Needed**: A threat actor doesn't need to be authenticated to the domain in order to roast the account, instead, they only need a valid username. 
- **Offline Cracking**: Once the encrypted hash is captured, cracking tools (like Hashcat: Mode 18200 or John the Ripper) can be used offline to avoid alerting the network. 
- **Legacy Systems**: This is often accidentally left enabled on older service accounts or accounts that are used for legacy app compatibility. 

#### **The Parser**
```python
def check_asrep_roasting(users, flags):

    for user in users:

        properties = user.get("Properties", {})

        username = properties.get("name", "UnknownUser")

        # Check AS-REP flag
        if properties.get("dontreqpreauth") == True:

            flags.append({
                "user": username,
                "vulnerability": "AS-REP Roasting",
                "description": f"{username} does not require Kerberos pre-authentication (AS-REP roastable)."
            })

```

#### **Security Risk**
AS-REP Roasting is a high-risk Active Directory vulnerability targeting user accounts with "Do not require Kerberos preauthentication" enabled. Attackers enumerate these accounts to request encrypted authentication data (AS-REP) from the Domain Controller and crack it offline, potentially obtaining plaintext passwords without needing legitimate network access.
1. **Key Aspects of AS-REP Roasting Security Risk**
Attack Technique: Exploits a configuration flaw where the Key Distribution Center (KDC) returns a Ticket Granting Ticket (TGT) encrypted with the user's password hash before verifying the user's identity.
No Initial Access Required: Unlike many attacks, the attacker does not need prior network credentials to perform this action.
Stealth and Persistence: The attack is largely offline, making it difficult to detect with traditional monitoring. It is frequently used by APT groups for lateral movement and privilege escalation.
High Impact: Successful cracking results in immediate credential theft of the targeted account.

2. **Detection and Mitigation Strategies**
Enforce Pre-Authentication: Ensure the "Do not require Kerberos preauthentication" setting is disabled for all user accounts.
Audit Vulnerable Accounts: Use PowerShell to locate accounts with DONT_REQ_PREAUTH enabled:
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth.
Monitor Events: Look for Windows Security Event ID 4768 (A Kerberos authentication ticket was requested), specifically when pre-authentication is not required.
Strengthen Passwords: Enforce strong, complex passwords for service accounts that might legitimately require this setting, making offline cracking infeasible.

#### **Mitigation**
AS-REP Roasting (MITRE ATT&CK T1558.004) is mitigated primarily by enabling "Do not require Kerberos preauthentication" for all user accounts in Active Directory, preventing attackers from capturing encrypted AS-REP hashes. The core fix is ensuring the checkbox "Do not require Kerberos preauthentication" is unchecked.


### Vulnerability 4: Machine Account Quota
By default, any authenticated user is capable of joining up to ten machines to the domain. This can allow for the creation of rogue machines and elevated privileges. 

#### **Technical Logic**
Identifying the machine account quota vulnerability in SharpHound output involves checking a specific property on the Domain object. This setting determines if a non-privileged user can add their own computer accounts to the domain, which is a common pre-requisite for Resource-Based Constrained Delegation (RBCA) attacks. Things to note include: 
1. **JSON Property for Machine Account Quota**: In the `domain.json` file, look for the following key-value pair in the `Properties` block: 
- **Property**: `"machineaccountquota": 10` (ultimately, this can be any value greater than zero).
- **Default Value**: `10`
- **Logic**: When this value is set above zero, any user who's authenticated can create up to that many computer accounts. Any domain where the flag isn't set to zero should be flagged. 

2. **How to Use in a Script**: When parsing the JSON, checking the `Properties` of the domain node is key. 
- **Vulnerability Indicator**: When `machineaccountquota > 0` is present, unprivileged users can create machine accounts. 
- **Why it Matters**: When a user creates a machine account, this gives a threat actor an object with a SPN (Service Principal Name). This opens the door for delegation attacks (like RBCD) and the creation of backdoor accounts that become harder to track than standard user accounts. 

3. **Key Attribute Mapping**: In the raw AD environment, this property maps to the attribute:
- **LDAP Display Name**: `ms-Ds-MachineAccountQuota`

#### **The Parser**
```python
def check_machine_account_quota(domains, flags):

    for domain in domains:

        properties = domain.get("Properties", {})

        domain_name = properties.get("name", "UnknownDomain")

        # Look for both naming formats
        quota = (
            properties.get("machineaccountquota")
            or properties.get("ms-DS-MachineAccountQuota")
            or 0
        )

        # Debug line (temporary)
        print("DEBUG:", domain_name, quota)

        if quota > 0:

            flags.append({
                "domain": domain_name,
                "vulnerability": "Machine Account Quota",
                "quota": quota,
                "description": f"{domain_name} allows users to create {quota} machine accounts."
            })
```

#### **Security Risk**
The Active Directory (AD) Machine Account Quota (MAQ) allows any authenticated user to create up to 10 computer objects (`ms-DS-MachineAccountQuota`) by default, posing a significant security risk by enabling attackers to create rogue machine accounts. These accounts can be used for privilege escalation, lateral movement, and persistent access via Resource-Based Constrained Delegation (RBCD) or Shadow Credentials.
1. **Core Security Risks**
- **Unauthorized Foothold**: Attackers with valid, low-privileged user credentials can create machine accounts without requiring local administrative rights, creating an immediate, legitimate, and silent foothold in the network.
- **Resource-Based Constrained Delegation (RBCD)**: Attackers use the new machine account to configure delegation rights, allowing them to impersonate other users (including admins) to access network services.
- **Shadow Credentials & Certificate Abuse**: Attackers can add credentials to the machine object, allowing them to authenticate via certificate-based methods or exploit vulnerabilities like CVE-2022–26923.
- **Privilege Escalation**: By default, new computer objects are added to the "Domain Computers" group, which may have excessive permissions or, in some cases, local admin rights to certain resources.

2. **How to Mitigate**
- **Set MAQ to 0**: Modify the `ms-DS-MachineAccountQuota` attribute to 0 to prevent unauthorized machine creation. This is the primary recommendation.
- **Delegate Rights**: Use active directory delegation to allow only specific, necessary users or groups (such as IT support) to join computers to the domain, rather than all authenticated users.
- **Monitor Creation**: Audit `ms-DS-CreatorSID` for anomalies, such as many machine accounts created by a single standard user, or monitor for `4741` events (A computer account was created).
- **Use LAPS**: Implement Microsoft's LAPS (Local Administrator Password Solution) to manage local admin passwords on workstations, reducing the risk of a new machine being used to compromise others.

#### **Mitigation**
Reducing the ms-DS-MachineAccountQuota attribute to 0 is the primary mitigation for Active Directory machine account quota risks, preventing unauthorized users from creating up to 10 machine accounts by default. This stops attackers from creating backdoor accounts for privilege escalation and RBCD (Resource-Based Constrained Delegation) attacks.
- **Set Quota to Zero**: Use ADSI Edit (`adsiedit.msc`) to set the `ms-DS-MachineAccountQuota` attribute to 0 on the domain object.
- **Delegate Permissions**: Instead of allowing all users to join machines, delegate the "Create Computer Objects" permission on specific Organizational Units (OUs) to authorized personnel (like Help Desk).
- **Monitor Activity**: Monitor for Event ID `4741` (Computer object created) to identify potential unauthorized computer account creation.
- **Verify Existing Account**s: Audit the `ms-DS-CreatorSID` attribute on existing machine accounts to identify accounts created by standard users.

### Vulnerability 5: Unpatched Domain Controllers (OS Version)
When an organization fails to patch their DCs or runs end-of-life operating systems, they're left vulnerable to known exploits like Zerologon or relay attacks.

#### **Technical Logic**
Discovering unpatched DCs through SharpHound output involves targeting the `computers.json` file and looking for specific properties tied to the OS. SharpHound doesn't directly scan for missing KB updates, it does collect the OS version strings that can reveal if a DC is running an outdated or EoL platform. Things to note include:
1. **The JSON Properties for OS Version**: In the `computers.json` file, looking at the `Properties` block for each machine that contains `"isdc": true`. It's important to look for:
- **`operatingsystem`**: This contains the friendly name of the OS (such as `"Windows Server 2012 R2 Standard"`). 
- **`operatingsystemversion`**: This contains the specific build number (such as `"6.3 (9600)"`).

2. **Script Checking**
- **Filter for DCs**: Only look for this in objects that contain the property `"isdc"` set to `true`. 
- ** Flag EoL Versions**: Flagging any DC where `operatingsystem` contains: 
  - `Windows Server 2008` or `2008 R2`
  - `Windows Server 2012` or `2012 R2` (Recently reached EoL) 
- **Check Build Numbers**: Using `operatingsystemversion` to identify if a system is missing major service packs or is an older build of a modern OS (such as early versions of Server 2016).

3. **Vulnerability Indicator**: There are a couple of indicators of vulnerabilities here:
- **Legacy OS**: If a DC is running an EoL OS, it's vulnerable to critical exploits (such as EternalBlue) for which there are no more publicly available patches. 
- **Missing Patches**: Even on newer OS versions, older build numbers suggest systems that haven't been recently updated, which makes them open to escalation paths like Zerologon or NoPac. 

4. **Mapping to LDAP**: If necessary, cross-referencing with a live LDAP query, these properties can be mapped to:
- `operatingSystem`
- `operationgSystemVersion`

5. **Values to Flag:** When searching for vulnerable OS versions (`2000`, `2003`, `2008`, and `2012`) a substring match on `operationsystem` properties can be used. Many DCs will have specific editions (such as Enterprise or R2) that might be missed by an exact string match. 

#### **The Parser**
```python
def check_outdated_os(computers, flags):

    outdated_versions = [
        # Vulnerable Systems
        "Windows XP",
        "Windows Vista",
        "Windows 7",
        "Windows 8",
        "Windows 8.1",

        # Vulnerable Servers
        "Windows Server 2003",
        "Windows Server 2008",
        "Windows Server 2008 R2",
        "Windows Server 2012",
        "Windows Server 2012 R2",
        "Windows Server 2016",

        # Vulnerable Non-Windows Systems
        "Ubuntu 14",
        "Ubuntu 16",
        "CentOS 6",
        "CentOS 7"
        ]

    for computer in computers:

        props = computer.get("Properties", {})

        computer_name = props.get("name", "Unknown")
        domain_name = props.get("domain", "UnknownDomain")

        os_name = props.get("operatingsystem")

        # Skip if OS is null
        if not os_name:
            continue

        print(f"DEBUG: {computer_name} - {os_name}")

        # Check partial match
        for outdated in outdated_versions:

            if outdated in os_name:

                flags.append({
                    "computer": computer_name,
                    "domain": domain_name,
                    "vulnerability": "Outdated OS",
                    "operatingsystem": os_name,
                    "description": f"{computer_name} in {domain_name} is running an outdated OS: {os_name}"
                })

                break
```

#### **Security Risk**
Using an outdated operating system (OS) for a Domain Controller (DC) or within an Active Directory (AD) environment creates a high-stakes security gap because the DC serves as the literal keys to the kingdom. If a DC is compromised, the attacker gains control over the entire identity infrastructure, allowing them to modify, corrupt, or destroy the AD database.
1. **Critical Security Risks**
- **Weaponized Vulnerabilities**: Systems that are End-of-Life (EOL) no longer receive security patches. Attackers actively seek these known flaws because they remain permanently open. Research shows EOL systems are 4x more likely to be weaponized by attackers.
- **Legacy Protocol Exploits**: Outdated OS versions often rely on insecure legacy protocols like NTLMv1 or SMBv1 (exploited by WannaCry and EternalBlue).
- **Broken Authentication**: Modern security hardening (e.g., Kerberos PAC signatures, RPC sealing) applied to newer DCs can cause authentication to fail when communicating with unpatched or outdated DCs in the same forest.
- **Lateral Movement**: A single outdated endpoint or server provides an entry point for attackers to move laterally across the network to more sensitive systems.

2. **Operational & Performance Impacts**
- **Inconsistent Patch Levels**: Keeping DCs on different Cumulative Update (CU) levels can break Kerberos tickets and prevent authentication across different sites.
- **Software Incompatibility**: Modern administrative tools and security software (like advanced EDR or modern AV) may not support older OS versions, leaving you with "blind spots" in your monitoring.
- **Performance Degradation**: Older systems are not optimized for modern hardware or processes, leading to slower authentication times and potential system instability. 

3. **Legal & Compliance Dangers**
- **Regulatory Penalties**: Frameworks like GDPR or HIPAA require provable security controls. Running unsupported systems can lead to failed audits and heavy fines.
- **Reputational Damage**: A breach caused by a preventable "open door" like an EOL server often leads to a permanent loss of customer trust.

#### **Mitigation**
Mitigating the risks of an outdated operating system (OS) on a Domain Controller (DC) requires a multi-layered defense strategy focused on isolation, hardening, and rapid decommissioning. Because these systems no longer receive security patches, you must implement compensating controls.
1. **Immediate Isolation & Network Control**
- **VLAN Segmentation**: Move outdated DCs to a dedicated, isolated Virtual Local Area Network (VLAN) to impede lateral movement.
- **Restrict Internet Acces**s: Block all outbound internet connections from DC subnets. If access is required, use a proxy with strict DNS filtering.
- **Firewall Hardening**: Use host-based firewalls to block all unauthenticated DCE/RPC traffic from untrusted sources and limit communication to only necessary ports and authorized systems. 
Practical 365

2. **Protocol & Service Hardening** 
- **Disable Legacy Protocols**: Turn off insecure protocols like SMBv1 and NTLMv1. Restrict NTLM usage entirely where possible.
- **Eliminate Unnecessary Services**: Disable the Print Spooler service on all DCs, as it is a frequent path for privilege escalation.
- **Enforce Security Signing**: Manually enforce SMB signing and LDAP channel binding to prevent man-in-the-middle attacks.

3. **Administrative & Account Security**
- **Tiered Administration**: Implement an administrative tiering model (Tier 0 for DCs) to prevent highly privileged accounts from logging into less secure workstations.
- **Least Privilege**: Strictly limit the number of users in highly privileged groups like Domain Admins and Enterprise Admins.
- **Enforce MFA**: Require Multi-Factor Authentication (MFA) for all administrative accounts.
- **Privileged Access Workstations (PAW)**: Require all DC management to be performed only from dedicated, highly secured endpoints.

4. **Monitoring & Defensive Measures**
- **Detailed Auditing**: Enable advanced security auditing to track all login attempts, object modifications, and changes to Group Policies.
- **SIEM Integration**: Send DC logs to a Security Information and Event Management (SIEM) tool for real-time analysis of abnormal patterns.
- **Protect LSASS**: Enable Windows Credential Guard or LSA Protection to safeguard credentials in memory from theft.
- **Physical Security**: Ensure DCs are in a locked, surveillance-monitored server room.

5. **Strategic Exit Plan**
- **Decommission Properly**: The ultimate mitigation is to demote the outdated DC using dcpromo and perform a metadata cleanup to remove all references from the AD forest.
- **Clean Rebuilds**: : Avoid in-place upgrades; instead, promote new servers with modern OS versions (like Windows Server 2022) to take over the roles.

### Bonus Vulnerabilities (Future Additions)
1. **ADCS Vulnerabilities (The ESC Attacks**: In recent SharpHound versions (v4+), it also collects data for Certificate Services. These are generally high-impact because they can lead to full domain compromise. For these, it's important to search `adcs.json` or `edges` for: 
- **`Enroll` and `ManageCertificates`**: These ACEs on a CA (Certificate Authority) or Certificate Template can indicate possible ESC1, ESC2, or ESC3 vulnerabilities. 
- **`Enrollable`**: An edge from a template to a user/group. If the template allows SAN (Subject Alternative Name) specification (`msPKI-Certificate-Name-Flag` has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`), any user with `Enroll` can impersonate a DA (Domain Admin). 
- **`EDITF_ATTRIBUTESUBJECTALTNAME2`**: If this property in the CA objects is `true`, the CA is globally vulnerable to SAN impersonation (ESC6). 

2. **Group Policy Object (GPO) Abuses**: When a threat actor is capable of modifying a GPO, they can push malicious scripts and create local admin accounts on all computers that the GPO is touching. Things to look for include: 
- **`GPLink`**: This identifies which OUs (Organizational Units) or Domain a GPO is applied to. 
- **`WriteDacl`, `GenericWrite`, and `GenericAll` on GPOs**: If a user who isn't an admin has these rights over a GPO, they have a direct path to `AdminTo` on every machine linked to it. 
- **`GPP Passwords**: Older SharpHound data can contain the presence of `groups.xml` or `scheduledtasks,xml` in SYSVOL; this can house hardcoded credentials that are encrypted with a publicly known AES key. 

3. **Dangerous OS Versions (Build-Specific)**: Outside of the major versions listed above, there are several modern risks, including: 
- **Windows Server 2025 (`BadSuccessor`)**: Although it's newer, SharpHound can flag the `dMSA` (delegated Managed Service Account) features. When unprivileged users have `CreateChild` on an OU, they can compromise any user in the domain with this feature. 
- **Build 10.0.14393 (Server 2016)**: Early versions of this are highly vulnerable to NoPac (sAMAccountName spoofing) unless it's fully patched. 
- **`IsSingleLabelDomain`**: This is a property in the Domain object. Single-label domains (such as one being named `CORP` instead of `CORP.LOCAL`) are more prone to name resolution attacks, such as WPAD spoofing. 

---

## SleuthHound
This component of DomainSleuth is the automated logic engine that parses through data for misconfigurations. SleuthHound is designed to ingest SharpHound JSON data and identify specific, high-impact AD misconfigurations that can lead to privilege escalation, or even domain compromise.

### Features & Detections
The current version of the script identifies the following vulnerabilities:
- **AS-REP Roasting**: Users that have `dontreqpreauth` set to True.
- **Unconstrained Delegation**: Computer objects trusted to impersonate users across the network. 
- **ACE Abuse**: Identification of dangerous permissions, such as `GenericAll`, `WriteDacl`, and `WriteOwner`. 
- **Machine Account Quota**: Identification of non-zero quotas on the Domain object. 
- **Outdated Operating Systems**: Detection of legacy systems (such as 2008, 2012, and more) based on the OS version strings. 

### Setup and Usage
1. **Preparation**: Ensure your SharpHound JSON files are unzipped and located in the input directory. You can do so using with:
  - **Windows** (Replace `<sharphound_zip> with the appropriate file name. 
  ```bash
  Expand-Archive -Path ".\<sharphound_zip>.zip" -DestinationPath ".\input" -Force
  ```

  - **Linux (Terminal)**: If you don't have `unzip` installed, run `sudo apt install unzip` first. After, run:
  ```bash
  unzip <sharphound_zip>.zip -d ./input
  ```

2. **Run the Script**: In the SleuthHound directory, run the following command:
  - **Windows**:
  ```bash
  python SleuthHound.py
  ```

  - **Linux**:
  ```bash
  python3 SleuthHound.py
  ```

3. **Review Output**: SleuthHound will output a standardized list of vulnerabilities, including the type of risk, source of the risk, and the target object. Each of the five vulnerabilities are output into their own respective file as well as in a centralized `flags.txt` file. You can view these by using:
```bash
cd output && ls
```

### Source Code 
If you would prefer to create the file yourself, you can do so in two simple steps:
1. **Create the file**: In the SleuthHound directory, simply create the file with:
```bash
nano SleuthHound.py
```

2. **Populate the File**: Simply add the following script to your new file:
<details>
<summary>Click to expand SleuthHound.py Source Code</summary>
```python
import json
import os
import glob

# Folder paths
INPUT_FOLDER = "input"
OUTPUT_FOLDER = "output"

def load_json_by_type(file_type):
    pattern = os.path.join(INPUT_FOLDER, f"*_{file_type}.json")

    files = glob.glob(pattern)

    if not files:
        raise FileNotFoundError(f"No {file_type}.json file found.")

    latest_file = max(files, key=os.path.getctime)

    print(f"Loading {latest_file}")

    with open(latest_file, 'r') as f:
        data = json.load(f)

    # IMPORTANT: return only the actual objects
    return data.get("data", [])

def save_flags(flags, filename="flags.json"):
    path = os.path.join(OUTPUT_FOLDER, filename)
    with open(path, 'w') as f:
        json.dump(flags, f, indent=4)
    print(f"Flags saved to {path}")

# Vulnerability Number One: Excessive User Rights and Permissions
def check_excessive_permissions(users, flags):

    dangerous_rights = [
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "AllExtendedRights"
    ]

    for user in users:

        properties = user.get("Properties", {})
        username = properties.get("name", "UnknownUser")

        aces = user.get("Aces", [])

        # Use a SET to prevent duplicates
        found_rights = set()

        for ace in aces:

            right = ace.get("RightName")

            if right in dangerous_rights:
                found_rights.add(right)

        # Only add a flag if something dangerous was found
        if found_rights:

            flags.append({
                "user": username,
                "vulnerability": "Excessive Permissions",
                "permissions": list(found_rights),
                "description": f"{username} has dangerous rights: {', '.join(found_rights)}"
            })

# Vulnerability Number Two: Weak Password Policies (AS-REP Roasting)
def check_asrep_roasting(users, flags):

    for user in users:

        properties = user.get("Properties", {})

        username = properties.get("name", "UnknownUser")

        # Check AS-REP flag
        if properties.get("dontreqpreauth") == True:

            flags.append({
                "user": username,
                "vulnerability": "AS-REP Roasting",
                "description": f"{username} does not require Kerberos pre-authentication (AS-REP roastable)."
            })

# Vulnerability Number Three: Unconstrained Delegation
def check_unconstrained_delegation(users, flags):

    for user in users:

        properties = user.get("Properties", {})

        username = properties.get("name", "UnknownUser")

        if properties.get("unconstraineddelegation") == True:

            flags.append({
                "user": username,
                "vulnerability": "Unconstrained Delegation",
                "description": f"{username} has unconstrained delegation enabled (high risk)."
            })

# Vulnerability Number four: Machine Account Quota
def check_machine_account_quota(domains, flags):

    for domain in domains:

        properties = domain.get("Properties", {})

        domain_name = properties.get("name", "UnknownDomain")

        # Look for both naming formats
        quota = (
            properties.get("machineaccountquota")
            or properties.get("ms-DS-MachineAccountQuota")
            or properties.get("ms-ds-machineaccountquota")
            or 0
        )

        # Debug line (temporary)
        # print("DEBUG:", domain_name, quota)

        if quota > 0:

            flags.append({
                "domain": domain_name,
                "vulnerability": "Machine Account Quota",
                "quota": quota,
                "description": f"{domain_name} allows users to create {quota} machine accounts."
            })
# Vulnerability Number Five: Outdated OS
def check_outdated_os(computers, flags):

    outdated_versions = [
        # Vulnerable Systems
        "Windows XP",
        "Windows Vista",
        "Windows 7",
        "Windows 8",
        "Windows 8.1",

        # Vulnerable Servers
        "Windows Server 2003",
        "Windows Server 2008",
        "Windows Server 2008 R2",
        "Windows Server 2012",
        "Windows Server 2012 R2",
        "Windows Server 2016",

        # Vulnerable Non-Windows Systems
        "Ubuntu 14",
        "Ubuntu 16",
        "CentOS 6",
        "CentOS 7"
        ]

    for computer in computers:

        props = computer.get("Properties", {})

        computer_name = props.get("name", "Unknown")
        domain_name = props.get("domain", "UnknownDomain")

        os_name = props.get("operatingsystem")

        # Skip if OS is null
        if not os_name:
            continue

        # print(f"DEBUG: {computer_name} - {os_name}")

        # Check partial match
        for outdated in outdated_versions:

            if outdated in os_name:

                flags.append({
                    "computer": computer_name,
                    "domain": domain_name,
                    "vulnerability": "Outdated OS",
                    "operatingsystem": os_name,
                    "description": f"{computer_name} in {domain_name} is running an outdated OS: {os_name}"
                })

                break

def main():
    # Ensure output folder exists
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    # Load SharpHound data dynamically
    users = load_json_by_type("users")
    computers = load_json_by_type("computers")
    domains = load_json_by_type("domains")

    # print("DEBUG domains length:", len(domains))
    # print("DEBUG domains first item:", domains[0])

    print(f"Loaded {len(users)} users")
    print(f"Loaded {len(computers)} computers")
    print(f"Loaded {len(domains)} domains")

    # --- Separate flags for each vulnerability type ---
    excessive_flags = []
    asrep_flags = []
    delegation_flags = []
    machine_flags = []
    outdated_flags = []

    # --- Run misconfiguration checks ---
    check_excessive_permissions(users, excessive_flags)

    # --- Run AS-REP Check ---
    check_asrep_roasting(users, asrep_flags)

    # --- Run Unconstrained Delegation Check ---
    check_unconstrained_delegation(users, delegation_flags)

    # --- Run Machine Account Quota Check ---
    check_machine_account_quota(domains, machine_flags)

    # --- Run Outdated OS Check ---
    check_outdated_os(computers, outdated_flags)

    # --- Combined Flag File ---
    all_flags = excessive_flags + asrep_flags + delegation_flags + machine_flags + outdated_flags

    # --- Save results to separate files ---
    save_flags(excessive_flags, "excessive_permissions.json")
    save_flags(asrep_flags, "asrep_roasting.json")
    save_flags(delegation_flags, "unconstrained_delegation.json")
    save_flags(machine_flags, "machine_account_quota.json")
    save_flags(outdated_flags, "outdated_os.json")

    # --- Save the master file ---
    save_flags(all_flags, "flags.json")
    
    print(f"Total vulnerabilities identified: {len(all_flags)}")

if __name__ == "__main__":
    main()
                         
```

