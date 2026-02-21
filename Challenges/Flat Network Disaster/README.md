# Flat Network Disaster: Risk and Security Analysis from a GRC Perspective
## Scenario
My group was given the following startup network:
- 1 Router
- 1 Firewall
- 1 Web Server
- 1 Database Server
- 8 Internal Systems
- All systems on the same network
- No VLANs
- No segmentation

The task is to build the topology in Packet Tracer or a diagram tool, identify at least 8 risks, and show how lack of segmentation increases:
- Lateral movement risk
- Insider threat risk
- Ransomware spread risk

The design represents a common learning scenario where a flat network is intentionally vulnerable. This allows us to explore fundamental security principles and demonstrate the value of segmentation, access controls, and proper network architecture.

ISO 27001 Annex A mappings are required to show alignment between risks and established security controls.

---

## Segmentation Vulnerabilities
The flat network topology creates multiple security weaknesses. These vulnerabilities illustrate why segmentation and proper controls are essential in modern network design.

### Lateral Movement Risk
- All devices share the same subnet
- No VLANs or network boundaries
- Compromised device can reach others freely
- Database and web servers accessible from internal systems
- Single breach can escalate to domain-wide compromise

Lateral movement allows attackers to hop between systems after initial access. Without segmentation, there are no internal barriers to restrict system-to-system communication. This increases the likelihood of domain takeover and data exposure.

ISO 27001 mappings:
- A.13.1.1 Network Controls
- A.13.1.3 Segregation in Networks

---

### Insider Threat Risk
- Any internal user can access other systems
- No restrictions on resource access
- Database and web servers exposed to internal PCs
- Lack of monitoring or internal firewalls
- Privilege escalation easier due to weak controls

Insider threats exploit the absence of segmentation and access controls. A malicious or compromised internal user can move freely within the network. Sensitive systems become targets for data theft or operational disruption.

ISO 27001 mappings:
- A.12.1 Logging and Monitoring
- A.11.2 Physical and Logical Access Segregation

---

### Ransomware Spread Risk
- Flat network enables rapid malware propagation
- No segmentation to contain infections
- Services and servers exposed across the network
- Firewall defaults may allow external communication
- Entire domain at risk of encryption or disruption

Ransomware thrives in environments without segmentation. Once a single system is infected, malware can spread across the network. Critical services and data become vulnerable to encryption or loss.

ISO 27001 mappings:
- A.8.21 Security of Network Services
- A.12.6 Technical Vulnerability Management

---

## Vulnerability List and Analysis
### Vulnerability One: Lack of Firewall ACLs and Rules
Default firewall configurations could allow unwanted traffic.  
This creates a risk that attackers can access internal systems due to lack of port and service filtering.

ISO 27001:
- A.13.1.1 Network Controls
- A.9.1 Access Control

Risk considerations:
- High likelihood due to default settings
- High impact if unauthorized access occurs
- Critical risk without proper configuration

---

### Vulnerability Two: Flat Network and No VLANs
All systems share the same subnet and network space.  
This means any compromised device can reach others without barriers.

ISO 27001:
- A.13.1.1 Network Controls
- A.13.1.3 Segregation in Networks

Risk considerations:
- High likelihood of lateral movement
- Critical impact if sensitive systems are reached
- High overall risk

---

### Vulnerability Three: Single Point of Failure
One router and one firewall handle all traffic.  
Device failure would take down the entire network due to lack of redundancy.

ISO 27001:
- A.17.1 Business Continuity
- A.12.1 Operational Procedures

Risk considerations:
- High impact on availability
- Moderate likelihood of failure
- High risk for business operations

---

### Vulnerability Four: No DMZ or Proxy Server
No buffer between internal network and internet.  
Attackers could reach internal resources directly from external sources.

ISO 27001:
- A.8.23 Web Filtering
- A.8.22 Segregation of Networks
- A.8.20 Network Security

Risk considerations:
- High exposure to external threats
- Critical impact if compromised
- High risk for domain takeover

---

### Vulnerability Five: No Segmentation or Internal Firewalls
Only edge firewall exists. Internal systems are not isolated.  
This enables lateral movement and malware propagation.

ISO 27001:
- A.12.1 Logging and Monitoring
- A.11.2 Physical and Logical Access Segregation

Risk considerations:
- High likelihood of system hops
- High impact from lateral movement
- Critical risk without internal controls

---

### Vulnerability Six: Exposed Web Server
Web server accessible by all internal systems.  
Attacks on the web server could pivot to other resources.

ISO 27001:
- A.12.6 Technical Vulnerability Management

Risk considerations:
- High exposure
- Critical impact if compromised
- Common attack vector

---

### Vulnerability Seven: Exposed Database Server
Database accessible by all PCs and web server.  
Sensitive data could be accessed if any endpoint is compromised.

ISO 27001:
- A.8.2 Information Classification
- A.12.3 Backup Protection

Risk considerations:
- Critical data exposure risk
- High impact on confidentiality
- Strong candidate for segmentation

---

### Vulnerability Eight: Insecure Network Services
Network services are exposed and easily accessible.  
Attackers can target services due to lack of controls.

ISO 27001:
- A.8.21 Security of Network Services

Risk considerations:
- High likelihood of exploitation
- High impact on service integrity
- Requires service hardening

---

## Lessons Learned
This topology demonstrates the importance of:
- Network segmentation
- Access controls
- Internal firewalls
- Proper service configuration
- Redundancy and resilience

Security is not only about protecting the network edge. Internal controls and segmentation are essential to limit damage from breaches and prevent lateral movement.

ISO 27001 and ISO 31000 principles emphasize risk management and systematic controls. The risk register and topology analysis show how these frameworks apply to real-world network design.

---

## Conclusion
A flat network creates significant security risks. Without segmentation and controls, attackers can move freely and compromise critical systems. The lessons from this topology highlight the value of modern security architecture and risk management frameworks.

By mapping vulnerabilities to ISO 27001 controls and ISO 31000 principles, we demonstrate a structured approach to risk identification and mitigation.

This analysis supports the design of more secure networks and reinforces the importance of layered defenses.
