# Week 4 Group Project: Defensive Engineer Checklist
**Role: SOC L3 / Detection Engineering Lead**

## 1. Incident Overview & Executive Summary
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

## 2. Initial Incident Review
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

## 3. SIEM Visibility Gap Analysis
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
- PowerShell transcription and Azure AD auditing gaps reduced visibility into credential abuse and command activity.
- Domain controller log forwarding and immutable logging were absent, creating blind spots and enabling log tampering.
- Endpoint telemetry and Defender enforcement did not capture malware staging, scheduled tasks, or credential dumping activity.
- Data exfiltration occurred without DLP or egress controls, allowing large outbound transfer despite detection of volume.
- Memory artifacts confirmed Mimikatz execution, but corresponding process and telemetry logs were not ingested into the SIEM, limiting forensic reconstruction.

---

## 4. Detection Failure Analysis
Analysis of telemetry and logs reveals visibility and detection gaps that enabled privilege escalation and persistence.

Key detection and visibility gaps:
- Incomplete authentication and Azure AD auditing limited detection of password spraying and credential abuse.
- Absence of domain controller log ingestion (particularly DC02) created a blind spot for replication and privilege escalation activity.
- Limited PowerShell and command logging prevented full reconstruction of attacker actions.
- Scheduled task and persistence telemetry were not captured, allowing persistence mechanisms to operate undetected.
- Immutable logging and log forwarding protections were absent, enabling log tampering and forensic gaps.
- Defender enforcement and endpoint telemetry did not detect credential dumping or malware activity.
- DLP and egress controls were not present, permitting data exfiltration without prevention.
- SOC detection lag reduced response speed relative to attacker activity.
- Post-incident validation did not fully verify persistence artifacts or scheduled tasks, reducing confidence in complete remediation.
- KRBTGT single rotation left potential residual domain trust risk and ticket forgery concerns.

These findings demonstrate that while some telemetry existed, detection engineering coverage and operational monitoring were insufficient to identify domain compromise techniques such as DCSync, credential dumping, and Golden Ticket persistence.

### Detection Logic vs. Telemetry Availability
It's important to distinguish between three separate failure categories observed during this incident:

1. **Telemetry Not Enabled:** Certain logs (e.g., PowerShell transcription, enhanced Azure AD auditing, replication permission monitoring) were not configured or centrally ingested, preventing detection opportunities altogether.
2. **Telemetry Present but Not Correlated:** In several cases, relevant logs existed within Splunk or Defender, but correlation logic was insufficient to link related events (e.g., multiple failed logins followed by a success, abnormal replication activity patterns).
3. **Alert Generated but Not Operationalized:** Alerts such as Azure AD “impossible travel” were generated but not escalated effectively, indicating weaknesses in alert prioritization, triage workflow, or severity classification.

The failure was therefore not a complete absence of tooling, but a breakdown across configuration, detection engineering logic, and operational response processes.

### Endpoint Protection Control Boundary Failure
The execution of `Set-MpPreference -DisableRealtimeMonitoring $true` indicates that either Microsoft Defender tamper protection was not enforced or that Group Policy modification privileges were overly broad.

This represents a control boundary failure in three areas:
- Lack of strict privilege governance over GPO modification rights
- Absence of change monitoring on security policy objects
- Insufficient enforcement of tamper protection settings at the tenant or endpoint level

Endpoint protection tools are only effective when configuration integrity is actively protected and monitored. In this case, security configuration itself became a compromise vector.

---

## Relevant ISO 27001 Annex A Control References 
- **ISO 27001 Annex A 8.15: Logging and Monitoring:** 
  Logging and event data collection to support detection, forensic analysis, and operational visibility.
- **ISO 27001 Annex A 8.16: Monitoring Activities:**
  Continuous monitoring of systems and user activity to detect security events and policy violations.
- **ISO 27001 Annex A 5.17: Authentication Information:**
  Controls governing authentication mechanisms and protection of credentials to prevent unauthorized access.
- **ISO 27001 Annex A 5.15: Access Control:**
  Restriction and governance of user and system access based on least privilege and authorization.
- **ISO 27001 Annex A 8.2: Identity Management:**
  Management of user identities and access provisioning to ensure proper privilege allocation.
- **ISO 27001 Annex A 8.7: Protection Against Malware:**
  Controls for endpoint protection and malware prevention to reduce risk of compromise.
- **ISO 27001 Annex A 8.18: Technical Vulnerability Management:**
  Processes for identifying and remediating technical vulnerabilities in systems and applications.
- **ISO 27001 Annex A 8.9: Configuration Management:**
  Governance of system configurations to maintain security posture and prevent unauthorized changes.
- **ISO 27001 Annex A 8.12: Data Leakage Prevention:**
  Controls to prevent unauthorized data exfiltration and protect sensitive information.
- **ISO 27001 Annex A 8.20: Network Security:**
  Protection of network communications and monitoring to detect and prevent malicious activity.
- **ISO 27001 Annex A 5.24: Incident Management:**
  Structured processes for identifying, responding to, and recovering from security incidents.
- **ISO 27001 Annex A 5.25: Post-Incident Review:**
  Lessons learned and process improvements following security incidents to enhance resilience.

---

## 5. Recommended Improvements
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
# 30–60–90 Day Security Hardening Plan

| Phase | Improvement | Control Area | Risk Mitigated |
|-------|------------|--------------|----------------|
| 0–30 Days | Enable and centralize authentication auditing across Azure AD and all domain controllers | Logging & Monitoring | Undetected credential abuse and lateral movement (ISO 27001 Annex A 8.15, 8.16, 5.17) |
| 0–30 Days | Ensure log ingestion from all domain controllers, including DC02 | Logging & Monitoring | Blind spots in domain compromise visibility (ISO 27001 Annex A 8.15, 8.16) |
| 0–30 Days | Deploy detection rules for log clearing (Event ID 1102), DCSync activity, and abnormal Kerberos events | Detection Engineering | Persistence concealment and credential theft via replication abuse (ISO 27001 Annex A 8.16, 8.2) |
| 0–30 Days | Audit Microsoft Defender configuration and enable tamper protection | Endpoint Security | Endpoint control bypass and malware persistence (ISO 27001 Annex A 8.7, 8.18) |
| 0–30 Days | Validate SIEM correlation rules for credential abuse and privilege escalation | SIEM & Detection Engineering | Password spraying and unauthorized privilege elevation (ISO 27001 Annex A 5.17, 8.16) |
| 31–60 Days | Expand PowerShell transcription and script block logging | Logging & Forensics | Inability to reconstruct attacker command activity (ISO 27001 Annex A 8.15) |
| 31–60 Days | Implement scheduled task and persistence monitoring with SIEM correlation | Endpoint & Detection Engineering | Undetected persistence mechanisms (ISO 27001 Annex A 8.9, 8.16) |
| 31–60 Days | Enhance endpoint telemetry and behavioral detection capabilities | Endpoint Security | Advanced attacker evasion and lateral movement (ISO 27001 Annex A 8.7, 8.16) |
| 31–60 Days | Deploy detection rules for replication abuse and Golden Ticket indicators | Identity & Detection Engineering | Kerberos ticket forgery and long-term domain compromise (ISO 27001 Annex A 5.17, 8.2, 8.16) |
| 31–60 Days | Improve Active Directory configuration: restrict replication permissions, enforce MFA for privileged accounts, implement GMSA controls, and deploy PAM governance | Identity & Access Management | Unauthorized DCSync activity and privileged credential misuse (ISO 27001 Annex A 5.15, 5.18, 8.2) |
| 61–90 Days | Conduct purple team exercises to validate detection coverage | Security Validation | Unverified detection capability and control effectiveness (ISO 27001 Annex A 8.16) |
| 61–90 Days | Perform SOC tabletop exercises for domain compromise scenarios | Incident Readiness | Ineffective incident escalation and response coordination (ISO 27001 Annex A 5.24, 5.25) |
| 61–90 Days | Implement continuous detection engineering lifecycle processes | Security Operations Governance | Stagnant detection logic and alert drift (ISO 27001 Annex A 8.16) |
| 61–90 Days | Validate DLP and egress control effectiveness | Network & Data Protection | Large-scale data exfiltration over encrypted channels (ISO 27001 Annex A 8.12, 8.20) |
| 61–90 Days | Establish ongoing monitoring metrics (MTTD, MTTR, false positive rates) | SOC Performance Management | Lack of measurable detection maturity and accountability (ISO 27001 Annex A 8.16) |

This phased approach improves visibility, strengthens detection capabilities, and reduces organizational risk of future domain compromise.

### Identity-Centric Risk and Persistence Considerations
This compromise demonstrates that hybrid Active Directory environments are primarily vulnerable through identity abuse rather than malware-based intrusion. Credential access, replication abuse, and privilege escalation formed the core attack path.

Additionally, single rotation of the KRBTGT account is insufficient following a domain compromise. Failure to perform a double-rotation leaves the possibility that previously forged Kerberos tickets (Golden Tickets) remain valid within their lifetime window, sustaining residual domain persistence risk.

Effective remediation must therefore prioritize privileged identity governance, replication permission control, and continuous monitoring of domain trust boundaries.

---

## 6. SIEM & Monitoring Improvement Blueprint
This blueprint outlines and recommends suggestions for improving the detection coverage, correlation rules, and log ingestion to enhance visibility into domain compromise techniques and reduce future detection gaps. 

| Area | Improvement | Impact |
|------|------------|--------|
| Log Sources | Ingest logs from all domain controllers, Azure AD, endpoint telemetry, and security appliances with immutable storage. | Improves visibility into authentication abuse, replication activity, and endpoint events. |
| Detection Engineering | Deploy detection rules for DCSync, log tampering, Golden Ticket indicators, and credential dumping behaviors. | Enables early identification of domain compromise techniques. |
| Correlation Rules | Link authentication events, replication activity, and persistence mechanisms into high-confidence alerts. | Reduces detection latency and improves incident response effectiveness. |
| Alerting Strategy | Prioritize alerts for domain controller log clearing, replication anomalies, and abnormal Kerberos activity. | Focuses SOC response on high-risk domain compromise indicators. |
| Monitoring Coverage | Expand monitoring to include task creation, persistence artifacts, and endpoint behavioral telemetry. | Enhances detection of post-compromise activity and persistence mechanisms. |

The SIEM and monitoring improvements outlined above aim to strengthen visibility and detection capabilities across authentication, domain controller activity, and endpoint telemetry. By expanding log ingestion, enhancing detection rules, and improving correlation coverage, the organization can reduce blind spots that previously enabled undetected domain compromise. These improvements focus on early detection of credential abuse, replication activity, and persistence techniques, ensuring that security operations can identify and respond to threats with greater speed and accuracy.

### Detection Engineering Maturity Shift
The recommended improvements transition monitoring from isolated, event-based alerting to behavior-based and correlation-driven detection engineering.

This includes:
- Linking authentication anomalies across time windows
- Correlating identity abuse with privilege escalation indicators
- Monitoring replication rights and domain control plane behavior
- Reducing alert fatigue through severity tuning and contextual enrichment

The objective is not to increase alert volume, but to improve detection fidelity and investigative clarity by focusing on high-risk identity-centric attack paths.
