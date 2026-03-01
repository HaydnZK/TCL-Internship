# HTB: Overwatch
## Initial Enumeration: Nmap Scan
After deploying the **Overwatch** machine, I began initial enumeration using a basic TCP scan:

```bash
nmap -Pn 10.129.244.81
```

### Why `-Pn`?
The `-Pn` flag skips host discovery (ping checks). This is useful in lab environments like Hack The Box where ICMP may be blocked.

---

## Scan Results Summary
- **Host:** 10.129.244.81
- **Status:** Host is up (~63ms latency)
- **Filtered Ports:** 988 TCP ports filtered (no response)

### Open Ports Identified
| Port | Service | Notes |
|------|----------|-------|
| 53   | domain | DNS service |
| 88   | kerberos-sec | Kerberos authentication (Active Directory indicator) |
| 135  | msrpc | Microsoft RPC |
| 139  | netbios-ssn | NetBIOS session service |
| 389  | ldap | LDAP (Active Directory indicator) |
| 445  | microsoft-ds | SMB |
| 464  | kpasswd5 | Kerberos password service |
| 593  | http-rpc-epmap | RPC over HTTP |
| 636  | ldapssl | Secure LDAP |
| 3268 | globalcatLDAP | Global Catalog (AD) |
| 3269 | globalcatLDAPssl | Secure Global Catalog |
| 3389 | ms-wbt-server | RDP |

---

## Initial Observations
- Multiple Active Directory related services are exposed:
  - Kerberos (88)
  - LDAP (389, 636)
  - Global Catalog (3268, 3269)
  - SMB (445)
- RDP (3389) is open, which may be useful later if credentials are obtained.
- DNS (53) suggests the host may function as a Domain Controller.

### Likely Conclusion
This machine appears to be a **Windows Active Directory Domain Controller**.

---

## Next Enumeration Steps
- Perform a more detailed scan:
  ```bash
  nmap -sC -sV -Pn 10.129.244.81
  ```
- Enumerate SMB shares
- Attempt anonymous LDAP queries
- Investigate DNS for domain information

Goal: Identify attack paths to obtain the **user flag**, then escalate to retrieve the **root flag**.

### Detailed Nmap Scan
To gather deeper information about exposed services and versions, I ran:
```bash
nmap -sC -sV -Pn 10.129.244.81
```

### Why These Flags?
- `-sC` → Runs default NSE scripts (useful for SMB, RDP, LDAP, etc.)
- `-sV` → Attempts service version detection
- `-Pn` → Skips host discovery (treats host as online)

---

## Updated Scan Results
### Domain & Identity Information
| Field | Value |
|-------|--------|
| Domain Name | overwatch.htb |
| NetBIOS Domain | OVERWATCH |
| Computer Name | S200401 |
| FQDN | S200401.overwatch.htb |
| OS Version | Windows Server (10.0.20348) |

---

## Key Service Details
### DNS (53)
- Service: Simple DNS Plus
- Confirms the host is acting as DNS for the domain

### Kerberos (88)
- Microsoft Windows Kerberos
- Confirms Active Directory authentication is in use

### LDAP (389/3268)
- Microsoft Active Directory LDAP
- Domain: overwatch.htb
- Site: Default-First-Site-Name

This strongly indicates the machine is functioning as a **Domain Controller**.

### SMB (445)
- SMB2 message signing **enabled and required**
- Prevents simple relay attacks

### RDP (3389)
Nmap RDP script revealed:
- DNS_Computer_Name: S200401.overwatch.htb
- NetBIOS_Computer_Name: S200401
- Product Version: 10.0.20348
- Valid SSL certificate for S200401.overwatch.htb

RDP is exposed, but authentication will be required.

---

## Initial Conclusions
This machine is almost certainly a **Windows Active Directory Domain Controller**.
- It is hosting:
  - DNS
  - LDAP
  - Kerberos
  - SMB
  - RDP
- SMB signing is enforced.
- No obvious misconfigurations detected from Nmap alone.

---

## Attack Surface Summary
Current access level: **Unauthenticated network access**

Logical next enumeration targets:
- LDAP (possible anonymous bind)
- Kerberos (user enumeration / pre-auth attacks)
- SMB (share enumeration)

Goal: Identify valid domain users → Leverage AD attack paths → Obtain user flag → Escalate to root flag.

---

## LDAP Enumeration: Root DSE Query
After installing `ldap-utils`, I queried the LDAP Root DSE to gather metadata about the Active Directory environment.

### Base Query (Root DSE)
```bash
ldapsearch -x -H ldap://10.129.244.81 -s base
```

#### Results Observed
The query returned LDAP metadata instead of user objects. Key fields included:

#### Supported Features
- supportedSASLMechanisms
- supportedLDAPVersion
- supportedControl
- supportedCapabilities
- supportedLDAPPolicies

These fields describe:
- Authentication mechanisms available (SASL/NTLM/Kerberos support)
- LDAP protocol versions supported
- Controls and capabilities the directory exposes

This confirms Active Directory functionality but does not leak identities.

### Directory Structure Metadata
The response also revealed:

- Schema subentries (CN=Schema, CN=Configuration)
- Aggregate schema information
- Server site and configuration details

This is standard AD metadata and confirms the presence of:

- Schema container
- Configuration container
- Sites and Services structure

No user data was exposed.

### Server Information
- Server Name: S200401
- Site: Default-First-Site-Name
- Containers:
  - CN=Servers
  - CN=Sites
  - CN=Configuration

This confirms the host is a Domain Controller within the Default-First-Name site.

### Domain Components
- DC=overwatch
- DC=htb

This is the domain base for future LDAP queries once authenticated.

### Conclusions
- LDAP is active and responding
- Anonymous subtree searches for user objects are restricted
- Root DSE metadata is readable
- Domain Controller confirmed
- No user enumeration via anonymous LDAP

### Strategic Impact
Since LDAP does not allow anonymous user dumps:

Next targets for identity discovery:
- SMB (port 445)
- RPC (port 135)

Both may leak domain or user information depending on configuration.

### Next Steps
- Attempt SMB share enumeration
- Test RPC user/domain queries
- Continue external enumeration before authentication attempts

Goal: Identify any identity leaks that can lead to user enumeration.

---

## SMB Share Enumeration: Initial Findings
Using `smbclient -L \\10.129.244.81`, the following shares were discovered.

### Discovered Shares
| Share | Type | Comment | Notes |
|--------|------|---------|-------|
| ADMIN$ | Disk | Remote Admin | Administrative share (requires credentials) |
| C$ | Disk | Default share | System drive administrative share (requires credentials) |
| IPC$ | IPC | Remote IPC | Used for inter-process communication and RPC |
| NETLOGON | Disk | Logon server share | Stores domain logon scripts |
| SYSVOL | Disk | Logon server share | Group Policy and domain-wide scripts |
| software$ | Disk | (No comment) | Custom share; may contain useful files |

### Observations
- ADMIN$ and C$ are administrative shares → require credentials.
- SYSVOL and NETLOGON confirm Active Directory infrastructure.
- software$ is a non-standard share with no description → potential area of interest.
- IPC$ is normal for RPC communication and enumeration.
- SMB1 is disabled (modern configuration).

### Security & Enumeration Impact
- No anonymous file access discovered.
- Share names alone provide structure but not sensitive data.
- SYSVOL/NETLOGON may contain policy scripts (if accessible with credentials).
- software$ should be explored once authentication is available.

### Next Steps

- Attempt to list contents of software$ (if permissions allow):
  ```bash
  smbclient \\\\10.129.244.81\\software$
  ```
- Explore SYSVOL for policy files (if access permitted).
- Continue LDAP/RPC enumeration for identity discovery.
- Avoid brute forcing until user accounts are identified.

Goal: Identify potential data leakage and paths toward credential discovery.

---

## SMB & Service Configuration Discovery

After initial LDAP and SMB enumeration, further analysis of the `software$` share revealed a custom monitoring application and service configuration.

### SMB Share Findings
The `software$` share contained a directory named **Monitoring**, which included:
- EntityFramework.dll (Entity Framework components)
- SQLite database libraries (System.Data.SQLite.dll)
- A monitoring executable (overwatch.exe)
- Configuration files and supporting DLLs

This suggested a custom monitoring application running on the system.

### Monitoring Application Insights
The configuration file (`overwatch.exe.config`) revealed a service definition:
```xml
<add baseAddress="http://overwatch.htb:8000/MonitorService" />
```

#### Key observations:
- A service exists at port 8000
- Endpoint path: /MonitorService
- Likely WCF (Windows Communication Foundation) service
- Exposed over HTTP

This indicates an application-level service beyond standard SMB/AD infrastructure.

### Service Accessibility Testing
Attempts to reach the service:
```bash
curl http://overwatch.htb:8000/MonitorService
curl -I http://overwatch.htb:8000
```

both failed to return meaningful responses.

#### Possible explanations:
- Service requires SOAP/WCF requests
- Authentication required
- Firewall/internal access restrictions
- Service not responding to basic HTTP GET requests

### Security & Enumeration Impact
- SMB structure confirmed application deployment
- Service endpoint discovered via configuration
- No immediate HTTP response from service
- Monitoring application likely interacts with backend data

This is valuable intelligence, but not yet a foothold.

### Next Strategic Steps
- Investigate WCF/SOAP service interaction
- Explore RPC and other service surfaces
- Continue AD identity enumeration
- Avoid brute forcing inaccessible services

Goal: Identify interaction methods with the monitoring service and potential data exposure paths.

---

## Enumeration Progress: Summary
This document records steps taken during external enumeration of the target Active Directory environment and monitoring application.

### Domain & Network Discovery
#### Initial Nmap Scan
- Target IP: 10.129.244.81
- Hostname: overwatch.htb
- Services identified:
  - DNS (53)
  - Kerberos (88)
  - LDAP (389)
  - SMB (445)
  - RDP (3389)
  - RPC (135, 593)
- AD indicators:
  - Active Directory LDAP
  - Domain controller functionality
  - SMB signing enabled (mitigates relay attacks)

This confirmed an Active Directory environment with standard security controls.

### LDAP Enumeration
#### Root DSE Query
```bash
ldapsearch -x -H ldap://10.129.244.81 -s base
```

Results:
- supportedSASLMechanisms
- supportedLDAPVersion
- supportedControl
- supportedCapabilities
- directory metadata

Anonymous user dumps are restricted.

#### Subtree Query Attempt
```bash
ldapsearch -x -H ldap://10.129.244.81 -b "DC=overwatch,DC=htb"
```

Result:
- Operations error
- Requires successful bind

Conclusion:
- LDAP is active
- Anonymous user enumeration is blocked
- Authentication required for deeper queries

### SMB Share Enumeration
```bash
smbclient -L \\10.129.244.81
```

Shares discovered:
- ADMIN$
- C$
- IPC$
- NETLOGON
- SYSVOL
- software$

Attempts to read content from:
- SYSVOL
- NETLOGON

were denied (permissions).

software$ share was readable.

---

### software$ Share Contents
Directory: **Monitoring**

Files discovered:
- EntityFramework.dll
- EntityFramework.SqlServer.dll
- System.Data.SQLite.dll
- overwatch.exe
- overwatch.exe.config

These indicate:
- Custom monitoring application
- Entity Framework (database interaction)
- SQLite support
- Service configuration

### Application Configuration Discovery
File: overwatch.exe.config

Key service definition:
```xml
<add baseAddress="http://overwatch.htb:8000/MonitorService" />
```

Observations:
- WCF-style service endpoint
- HTTP service on port 8000
- Monitoring service interface

Basic HTTP GET attempts (curl) failed:
- No response
- Service likely requires SOAP/WCF interaction
- Possibly firewalled or authentication protected

### Service Discovery (DNS SRV)
```bash
dig @10.129.244.81 SRV _ldap._tcp.dc._msdcs.overwatch.htb
```

Result:
```
_ldap._tcp.dc._msdcs.overwatch.htb SRV 0 100 389 s200401.overwatch.htb
```

Additional records:
- s200401.overwatch.htb -> 10.129.244.81
- IPv6 addresses present (dual-stack configuration)

This confirms:
- Domain controller identity
- LDAP service registration
- DNS service discovery functioning

### RPC Enumeration
rpcclient attempts:
```bash
rpcclient 10.129.244.81
```

Result:
- NT_STATUS_ACCESS_DENIED
- SMB signature validation failure
- RPC requires credentials

No anonymous RPC access.

---

## Strategic Conclusions
### Discovered
- Active Directory infrastructure
- Domain controller hostname (s200401)
- LDAP service records
- Monitoring application
- Service endpoint (port 8000)
- SMB share structure

### Restricted
- LDAP user enumeration
- SMB directory content
- RPC queries
- Monitoring service via HTTP

Security posture appears reasonably hardened.

---

## Attack Surface Status
| Surface | Status | Notes |
|----------|---------|-------|
| LDAP | Restricted | Anonymous subtree denied |
| SMB | Partially accessible | software$ readable, others protected |
| RPC | Restricted | Requires authentication |
| HTTP Service | Non-responsive | Likely SOAP/WCF or firewalled |
| DNS | Informative | SRV records revealed infrastructure |

---

## Next Steps
### Identity Discovery
- Alternative LDAP approaches (if available)
- Kerberos username validation (post-identity)
- DNS service mapping (complete)

### Service Analysis
- WCF/SOAP interaction (if service accessible)
- RPC with authentication (later stage)
- Application logic review (post-access)

### AD Attack Planning
- AS-REP roasting (requires user list)
- Kerberoasting (requires service accounts)
- Password spraying (after identities)

---

## Lessons Learned
- Enumeration is iterative
- Security boundaries provide data
- Service discovery informs strategy
- Authentication is required for deeper access

Progress achieved in mapping infrastructure and understanding restrictions.

Further steps require identity discovery and service interaction.

---

## Static Analysis Notes: overwatch.exe
### Action Taken
Downloaded `overwatch.exe` from the `software$` share and ran:

strings overwatch.exe

Goal was to identify technologies, libraries, database usage, and any indicators of execution capability.

### .NET Framework Indicators
Observed:
- .NETFramework,Version=v4.7.2
- mscorlib
- System.*
- TargetFrameworkAttribute

Conclusion:
The application is a .NET Framework 4.7.2 binary. This means it can likely be decompiled to readable C# source code using standard .NET decompilers.

### WCF Service Indicators
Observed:
- System.ServiceModel
- ServiceHost
- ServiceContractAttribute
- OperationContractAttribute
- IMonitoringService

Conclusion:
The application appears to implement a WCF service. This explains why direct HTTP requests using curl did not return useful output. The service likely expects structured SOAP or specific service calls rather than simple GET requests.

### MSSQL Interaction
Observed:
- SqlConnection
- SqlCommand
- System.Data.SqlClient
- ExecuteReader
- ExecuteNonQuery
- connectionString

Conclusion:
The application connects to an MSSQL database and executes queries. This aligns with external hints referencing MSSQL behavior. Potential SQL injection vulnerabilities may exist within application logic depending on how queries are constructed.

### SQLite Support
Observed:
- System.Data.SQLite
- SQLiteConnection
- SQLiteCommand
- SQLiteDataReader

Conclusion:
The application may support SQLite in addition to MSSQL. This could indicate either local storage capability or multiple database configurations.

### PowerShell Execution Capability
Observed:
- System.Management.Automation
- RunspaceFactory
- CreateRunspace
- AddScript
- Invoke
- CreatePipeline

Conclusion:
The application has the ability to execute PowerShell scripts programmatically. If user-controlled input reaches these functions without proper validation, this could potentially lead to remote code execution.

### Process Monitoring and Control
Observed:
- ManagementEventWatcher
- StartProcessWatcher
- KillProcess
- WqlEventQuery
- processName

Conclusion:
The application monitors system processes and has the ability to terminate them. This suggests it operates with significant system interaction capabilities.

### Debug Symbol Path
Observed:
C:\Users\Administrator\source\repos\overwatch\overwatch\obj\x64\Release\overwatch.pdb

Conclusion:
The application was compiled by a user named Administrator in a development environment. Debug path information is embedded in the binary, suggesting it was not heavily hardened before deployment.

### Limitations of strings Analysis
The strings output does not reveal:
- Exact SQL query construction
- Whether parameterized queries are used
- How service methods are implemented
- How input flows through the application

Further analysis requires decompilation of the executable.

### Overall Assessment
The application is a .NET WCF service that interacts with MSSQL and has the ability to execute PowerShell. The likely attack surface involves application logic rather than infrastructure services such as LDAP or SMB. Further static analysis of the binary is required to identify potential unsafe input handling.

---

## Decompilation Commands Used
- `dotnet tool install -g ilspycmd`  
- `export PATH="$PATH:$HOME/.dotnet/tools"`  
- `source ~/.bashrc`  
- `ilspycmd overwatch.exe -o decompiled`

---

## Analysis Notes: OverWatch Decompiled Code
### Service Interface
IMonitoringService exposes three methods:
- StartMonitoring()
- StopMonitoring()
- KillProcess(string processName)

These are service entry points and represent the attack surface for the WCF service.

### SQL Usage and Vulnerabilities
#### LogEvent Method
SqlCommand is built with string concatenation:
`SqlCommand val2 = new SqlCommand("INSERT INTO EventLog (Timestamp, EventType, Details) VALUES (GETDATE(), '" + type + "', '" + detail + "')", val);`

This pattern is vulnerable to SQL injection because user-controlled data (type and detail) is inserted directly into the query without parameterization.

#### CheckEdgeHistory Method
SQL is also constructed dynamically when logging URLs:
`"INSERT INTO EventLog (Timestamp, EventType, Details) VALUES (GETDATE(), 'URLVisit', '" + text2 + "')"`

Again, string concatenation with data from the Edge history database could allow injection if not sanitized.

### PowerShell Execution
KillProcess constructs a PowerShell command:
`string text = "Stop-Process -Name " + processName + " -Force";`

This command is passed to:
`val2.Commands.AddScript(text);`

If processName is not validated, this is unsafe command construction and could allow execution of unintended commands through PowerShell.

### Database Credentials
The connection string is hardcoded:
`Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=TI0LKcfHzZw1Vv;`

This indicates:
- SQL Server is local
- A service account exists
- Database is SecurityLogs

Credentials are embedded in code, but exploitation would depend on database permissions and service behavior.

### Input Handling
Both SQL and PowerShell usage rely on direct string concatenation.

This is a common source of:
- SQL injection
- command injection
- unsafe query execution

However, identifying the vulnerability is not the same as having an immediate exploit path.

### Attack Surface Summary
- WCF service methods
- SQL query construction
- PowerShell command execution
- Service contract endpoints

The code demonstrates logical weaknesses in input handling, but exploitation would require understanding how the service is invoked and what input can be provided through legitimate interfaces.

### Next Analytical Steps
- Identify how service methods are called
- Determine input paths to SQL and PowerShell logic
- Analyze database permissions
- Evaluate service accessibility

