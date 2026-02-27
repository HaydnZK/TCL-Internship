

# Week 4 Group Project: Defensive Engineer Checklist
## Incident Summary
On March 14, the organization experienced a multi-stage Active Directory compromise that escalated from password spray activity to domain control within approximately six hours. The attacker compromised a service account, modified privileged groups, and cleared security logs on a domain controller. Directory replication (DCSync) was abused to extract credential material, and evidence indicates access to the KRBTGT account enabled domain authentication manipulation. Domain administrator credentials were used from a non-IT workstation, followed by malware deployment (NullHack.exe) and an encryption event consistent with ransomware. Network telemetry suggested possible data exfiltration.

Remediation included endpoint reimaging, password resets, administrative credential rotation, and Active Directory restoration from backup. However, KRBTGT rotation occurred only once and post-remediation analysis revealed valid Kerberos authentication for a hostname not present in Active Directory. The authentication was cryptographically valid and showed no signs of malware or brute force activity, indicating potential persistent compromise. The incident was classified as a persistent domain compromise.

Control weaknesses included limited authentication auditing, incomplete domain controller log ingestion, inconsistent endpoint protection enforcement, and absence of immutable logging. These gaps reduced detection capability and allowed the attacker to escalate privileges and maintain persistence.

### Role Summary (Defensive Engineer)
As a Defensive Engineer and Detection Engineering Lead, my role focused on identifying detection failures and visibility gaps that allowed the attack to proceed undetected. Analysis covered SIEM telemetry gaps, missed alerts, and insufficient coverage for domain compromise techniques such as DCSync and log tampering.

Deliverables included a Detection Failure Report, Logging and Telemetry Gap Analysis, 30 60 90 Day Security Hardening Plan, and SIEM and Monitoring Improvement Blueprint. These outputs aim to improve detection capabilities and strengthen security monitoring to reduce future risk.

## Incident Overview & Executive Summary
On March 14, the organization experienced a multi-stage Active Directory compromise that escalated from password spray activity to full domain control within approximately six hours.

The attack sequence included:
- Successful compromise of a service account
- Privileged group modification
- Security log clearing on a Domain Controller
- Abuse of directory replication permissions (DCSync)
- Access to the KRBTGT account
- Domain Admin authentication from a non-IT workstation
- Malware deployment (NullHack.exe)
- Organization-wide encryption event
- Possible large-scale data exfiltration

Indicators strongly suggest the attacker achieved domain dominance through replication abuse and Kerberos ticket manipulation.

Six months after remediation efforts, a valid Kerberos TGT was issued for a hostname not present in Active Directory. The authentication was cryptographically valid and showed no signs of brute-force or malware activity, indicating a likely persistent Golden Ticket scenario or incomplete KRBTGT remediation.

The incident has been classified as a persistent compromise due to continued evidence of unauthorized Kerberos trust within the domain.

---

## 1. Initial Incident Review
| Artifact | Finding | Evidence |
|---------|---------|-----------|
| Initial Access | Password spray -> r.sharma | Azure sign-in anomaly, failed logins |
| Privilege Escalation | Group modification (Backup Operators) | sql_svc facilitated change |
| Persistence | Scheduled task on DC02 | Survives reboots |
| Domain Indicators | Log clearing, ransomware, replication abuse | Domain-level compromise |
| Impact | Domain takeover + encryption | Operational disruption |

Notes:
The attack began with password spraying against WS-17, ultimately granting access to the r.sharma account. Once inside, the attacker generated an abnormal volume of TGS requests before successfully obtaining service access to srv_sql. From there, they escalated privileges by adding r.sharma to the Backup-Operators group and modifying group policy, which enabled further domain-level access. Security logs on DC01 were subsequently cleared, reducing forensic visibility. Using elevated privileges, the attacker created a large SQL dump and exfiltrated it over HTTPS. Administrative access was then observed on WS-17, after which a KRBTGT ticket was issued and a scheduled task was created on DC02 to establish persistence. The attacker leveraged these capabilities to deploy NullHack.exe across 23 endpoints, resulting in system-wide encryption and ransom activity. Although remediation steps were performed, six months later anomalies emerged, including issuance of a rogue Kerberos ticket for a non-existent workstation; suggesting residual or persistent compromise despite the absence of active malware.

---

## 2. SIEM Visibility Gap Analysis
Following analysis of the event timeline, associated log data, analyst communications, telemetry, and recovered artifacts, multiple visibility gaps were identified within the SIEM architecture. These gaps significantly limited early detection and hindered full reconstruction of attacker activity.

The absence of comprehensive authentication monitoring, incomplete domain controller log ingestion, limited PowerShell visibility, and insufficient endpoint telemetry collectively created conditions in which the adversary was able to escalate privileges, establish persistence, conduct data exfiltration, and ultimately deploy ransomware with minimal resistance.

The findings below outline the specific control weaknesses that contributed to this outcome.

| Control Area | Observed Visibility | Gap Identified | Impact |
|--------------|--------------------|---------------|--------|
| Azure AD / Cloud Identity | Azure sign-in anomaly observed; limited failed logon detail | No centralized Azure AD advanced auditing; no password spray correlation detection | Delayed identification of initial access vector |
| On-Prem Authentication | Single 4625 event observed; successful svc_sql authentication logged | Incomplete failed logon pattern visibility; no clear spray detection rule | Inadequate detection of credential abuse activity |
| Kerberos Monitoring | Some 4769 (TGS) events observed; replication activity logged (4662) | No 4768 (TGT issuance) or 4771 (pre-auth failures) observed; limited ticket lifecycle visibility | Reduced insight into ticket abuse and escalation activity |
| PowerShell / Command Logging | Limited PowerShell artifacts recovered from memory | No comprehensive PowerShell transcription or script block logging in SIEM | Inability to fully reconstruct attacker command activity |
| Endpoint Security | Defender present but inconsistently enforced | No visible tamper alerts; no logging of Defender disablement; no endpoint telemetry for ransomware staging | Malware deployment and execution occurred without early detection |
| Domain Controller Logging | Log clearing event (1102) recorded on DC01 | No immutable log storage; no prevention of log deletion; no logs ingested from DC02 | Forensic visibility lost; persistence established in blind spot |
| Persistence Monitoring | No logs showing scheduled task creation on DC02 | No scheduled task auditing or centralized ingestion from secondary DC | Persistence mechanism went undetected |
| Network & Exfiltration | Large outbound HTTPS transfer (~2.8GB) observed | No DLP enforcement; no egress blocking of unknown/self-signed destinations | Successful data exfiltration without prevention |
| SOC Operations | SOC identified anomalies ~30 minutes behind attacker actions | No automated correlation for spray, replication abuse, or DC log clearing | Attacker maintained operational advantage |

### Notes
- Limited PowerShell transcription logging significantly reduced visibility into attacker command execution.
- Absence of centralized Azure AD advanced auditing limited insight into cloud-based authentication abuse.
- Kerberos monitoring lacked full ticket lifecycle coverage, preventing early detection of credential misuse.
- DC02 did not appear to forward logs to the SIEM, creating a domain controller blind spot.
- Log clearing on DC01 was visible but not escalated immediately, indicating an alerting or triage failure.
- No evidence of immutable or write-once logging architecture was observed.
- Endpoint telemetry did not capture ransomware staging or scheduled task persistence activity.
- Although exfiltration volume was detected, lack of DLP controls allowed data loss to proceed uninterrupted.
- Memory artifacts from DC01 confirm execution of Mimikatz for credential dumping; however, no corresponding process creation logs, Defender alerts, file creation events, or script execution telemetry were ingested into the SIEM, indicating a critical lack of endpoint visibility on a domain controller during credential access activity.

---

## 3. Detection Failure Analysis
Analysis of the incident timeline, telemetry, and available logs reveals systemic visibility and detection gaps that enabled the attacker to escalate privileges, extract credentials, and maintain persistence with minimal resistance. While limited telemetry existed, it was insufficient to detect critical domain compromise techniques.

Key detection and visibility gaps:

- Incomplete authentication and Azure AD auditing limited visibility into initial credential abuse and password spray activity.
- Absence of comprehensive domain controller log ingestion (particularly from DC02) created a blind spot during privilege escalation and replication activity.
- Limited PowerShell and command execution logging prevented full reconstruction of attacker actions and tool usage.
- No scheduled task or persistence telemetry from DC02 allowed persistence mechanisms to operate undetected.
- Lack of immutable logging and log forwarding protections enabled log tampering and forensic visibility loss.
- Insufficient endpoint telemetry and Defender enforcement allowed credential dumping and malware execution without early detection.
- Absence of DLP and egress controls permitted large-scale data exfiltration without prevention.
- SOC detection and alerting lag (~30 minutes behind attacker activity) reduced the ability to respond in real time.
- IR processes did not validate scheduled task artifacts or persistence mechanisms during post-incident analysis, allowing potential residual persistence to go undetected and reducing confidence in complete remediation.
- KRBTGT rotation occurred only once during remediation, contrary to best practice double-rotation requirements, leaving potential risk of ticket reuse and persistent domain trust artifacts.

These gaps collectively demonstrate that while logs and telemetry existed in part, detection engineering and monitoring coverage were insufficient to identify and stop domain compromise techniques such as DCSync, credential dumping, and Golden Ticket-style persistence.

---

## 4. Recommended Improvements
To address the gaps in visibility and detections identified in this analysis, security controls and monitoring capabilities must be enhanced across authentication, endpoint telemetry, domain controller logging, and SIEM detection engineering.

Areas of improvement:
- Azure AD auditing: Implement auditing to improve visibility into authentication abuse and cloud identity attacks.
- DC log ingestion: Ensure comprehensive log ingestion and immutable logging to prevent loss of visibility and log tampering.
- PowerShell transcription: Enhance transcription and script block logging to enable reconstruction of attacker command activity.
- Task monitoring: Monitor task creations and modifications with SIEM correlation rules to detect anomalies and persistence mechanisms.
- Endpoint telemetry: Enhance telemetry to assist in detecting credential dumping and malware activity.
- Defender enforcement: Configure Defender policies consistently to strengthen endpoint protection.
- DLP and egress controls: Deploy controls to prevent large-scale data exfiltration and enforce data protection policies.
- Detection engineering rules: Implement rules to detect DCSync, replication abuse, and Golden Ticket indicators.
- SOC alerting: Enhance alerting to reduce latency between detection and response.
- IRP updates: Update IRP procedures to require verification of persistence mechanisms (including scheduled tasks and registry-based artifacts) during post-remediation validation.
- KRBTGT rotation: Enforce double-rotation to comply with best practices and eliminate persistent domain trust artifacts.
- AD Configurations: AD replication permissions, gMSAs (Group Managed Service Accounts), and MFA (Multifactor Authentication) should be implemented as well as forcing strict PAM (Privileged Access Management) to prevent DCSync attacks and replication. 

These improvements address the systemic monitoring and detection weaknesses that allowed domain compromise and persistence to occur, even after mitigation.

### 30-60-90 Day Security Hardening Plan
The following remediation strategy provides recommendations to address the critical security and visibility gaps identified in this analysis. These suggestions prioritize mitigation of high-risk control failures and detection weaknesses, progressing from immediate hardening to longer-term operational maturity.
- 30 Day Focus: Immediate stabilization and detection improvements, including log ingestion fixes, authentication auditing, and SIEM rule deployment for domain compromise techniques.
- 60 Day Focus: Expansion of telemetry, endpoint monitoring, and detection engineering capabilities to improve visibility into credential abuse and persistence mechanisms.
- 90 Day Focus: Operational maturity through purple team validation, IR process enhancements, and continuous detection engineering to sustain long-term security improvements.

#### 0-30 Days (Immediate Stabilization)
- Enable and centralize authentication auditing across Azure AD and domain controllers.
- Ensure log ingestion from all domain controllers (including DC02).
- Deploy detection rules for log clearing, DCSync activity, and abnormal Kerberos events.
- Audit Defender configuration and enable tamper protection.
- Validate SIEM correlation rules for credential abuse and privilege escalation.

#### 31-60 Days (Detection and Monitoring Enhancements)
- Expand PowerShell transcription and script block logging for command activity reconstruction.
- Implement scheduled task and persistence monitoring with SIEM correlation rules.
- Enhance endpoint telemetry and behavioral detection capabilities.
- Deploy detection rules for replication abuse and Golden Ticket indicators.
- Improve Active Directory configuration to mitigate DCSync risk through replication permission governance, GMSA controls, MFA enforcement, and PAM-based privilege management.

#### 61-90 Days (Maturity and Validation)
- Conduct purple team exercises to validate detection coverage.
- Perform SOC tabletop exercises for domain compromise scenarios.
- Implement continuous detection engineering lifecycle processes.
- Validate DLP and egress control effectiveness.
- Establish ongoing monitoring metrics (MTTD, MTTR, false positive rates).

This phased approach improves visibility, strengthens detection capabilities, and reduces organizational risk of future domain compromise.

---

## 5. SIEM & Monitoring Improvement Blueprint
This blueprint outlines and recommends suggestions for improving the detection coverage, correlation rules, and log ingestion to enhance visibility into domain compromise techniques and reduce future detection gaps. 

## 7. SIEM & Monitoring Improvement Blueprint

| Area | Improvement | Impact |
|------|------------|--------|
| Log Sources | Ingest logs from all domain controllers, Azure AD, endpoint telemetry, and security appliances with immutable storage. | Improves visibility into authentication abuse, replication activity, and endpoint events. |
| Detection Engineering | Deploy detection rules for DCSync, log tampering, Golden Ticket indicators, and credential dumping behaviors. | Enables early identification of domain compromise techniques. |
| Correlation Rules | Link authentication events, replication activity, and persistence mechanisms into high-confidence alerts. | Reduces detection latency and improves incident response effectiveness. |
| Alerting Strategy | Prioritize alerts for domain controller log clearing, replication anomalies, and abnormal Kerberos activity. | Focuses SOC response on high-risk domain compromise indicators. |
| Monitoring Coverage | Expand monitoring to include task creation, persistence artifacts, and endpoint behavioral telemetry. | Enhances detection of post-compromise activity and persistence mechanisms. |

The SIEM and monitoring improvements outlined above aim to strengthen visibility and detection capabilities across authentication, domain controller activity, and endpoint telemetry. By expanding log ingestion, enhancing detection rules, and improving correlation coverage, the organization can reduce blind spots that previously enabled undetected domain compromise. These improvements focus on early detection of credential abuse, replication activity, and persistence techniques, ensuring that security operations can identify and respond to threats with greater speed and accuracy.
