# Packet Capture Analysis Strategy
## Strategic Objectives & Technical Goals
**Mastering the Packet-Level Narrative**

#### Slide 1: **Core Objectives**
- **Strategic Intent Identification**: Shifting from passive observation to active threat hunting.
    - The goal is to move beyond just noticing odd activity. We want to anticipate attacker behavior and take proactive measures before damage occurs.
- **Protocol Mastery**: Hardening defenses against invisible DNS and high-volume traffic.
    - Understanding DNS and other protocols in depth allows us to detect subtle abuses. High-volume or hidden traffic often hides the most serious threats.
- **Evidence-Based Logic**: Replacing speculative hunches with data-driven investigation.
    - Decisions are grounded in measurable patterns, not guesswork. Every observation should tie back to real network activity or recorded events.
- **Operational Discipline**: Establishing a repeatable, rigorous process for consistent results.
    - Having a structured workflow ensures nothing is overlooked. It also allows teams to scale investigations without losing accuracy.

#### **Our Goals**
- **Baseline Mastery**: Defining Normal behavior to instantly spot the Abnormal.
    - Knowing what normal looks like is essential. Once baseline behavior is established, deviations stand out clearly.
- **Framework Alignment**: Correlating technical artifacts directly to MITRE ATT&CK techniques.
    - Linking observed activity to recognized frameworks makes findings actionable. It also supports reporting and cross-team collaboration.
- **Volume Analysis**: Distinguishing between Elephant exfiltration and Mice C2 heartbeats.
    - Large data transfers and small periodic check-ins look very different, but both can indicate malicious activity. Understanding the distinction improves detection.
- **Tool Integration**: Leveraging RITA and Zeek to automate long-term pattern detection.
    - Using automated tools helps monitor large networks continuously. They flag anomalies for analyst review, saving time and increasing accuracy.

---

## 1. **Precision Packet Analysis & Filtering Strategy**
This section focuses on how to turn overwhelming packet data into something meaningful through structured filtering and analysis. It builds a clear methodology around using the OSI model to isolate where activity is happening, then applying precise filters to cut through background noise and focus on what actually matters. It walks through how to analyze different protocols like TCP, UDP, DNS, and HTTP/S, showing how each one reveals different pieces of the story, from connection health to potential command and control activity. It also emphasizes the importance of combining filters with logical operators to move through data efficiently, helping you track attacker behavior, validate findings, and build a clean, evidence-based narrative from what would otherwise be a chaotic stream of traffic.

### Slide 2: Filtering Methodology
**Moving from Packet Collection to Network Storytelling**

#### **The Analyst's Mission**
- **Efficiency**: Drastically reducing MTTR through systematic pcap navigation.
    - By applying structured filters, analysts spend less time sifting through noise. The goal is to quickly zero in on suspicious activity and reduce time-to-resolution.
- **Contextualization**: Turning raw hex data into a coherent narrative of attacker behavior.
    - Raw packets tell little on their own, but when you connect the dots, a story emerges. This helps analysts understand the intent behind every network action.
- **Precision Analysis**: Ensuring every applied filter serves a specific investigative pivot.
    - Each filter should have a clear purpose. Random filtering can hide critical clues, so every rule is deliberate.

#### **The Strategic Roadmap**
- **L2-L7 Scoping**: Using the OSI model to partition the hunt and isolate the attack layer.
    - By focusing on a specific layer, you reduce irrelevant traffic and sharpen your view of the attack. Each layer has its own artifacts and behaviors to inspect.
- **Boolean Logic**: Applying AND/OR/NOT operators to surgically remove background noise.
    - Boolean filters let you combine criteria to fine-tune results. This precision ensures you catch what matters without getting overwhelmed.
- **Session Integrity**: Tracking handshakes and flags to verify successful connections.
    - Looking at the full session context confirms whether communication succeeded. Incomplete sessions can signal scanning or failed attacks.
- **Artifact Velocity**: Accelerating the discovery of malicious indicators within the firehose.
    - Efficient filtering lets analysts identify indicators faster. This speed is critical when investigating high-volume networks under active threat.

### Slide 3: The Analyst’s Lens: The OSI Model
**Using the OSI Model as a Technical Map for Isolation**

#### **Layered Investigation**
- **Transport Health (Layers 2-4)**: Assessing connection integrity and handshake stability.
    - Checking TCP/UDP behavior and ensuring sessions complete as expected reveals whether connections are legitimate or abnormal. Failed handshakes can indicate scanning or dropped attacks.
- **Application Intent (Layer 7)**: Analyzing protocol-specific payloads for malicious activity.
    - Looking at HTTP, DNS, or other application data uncovers what the traffic is actually doing. This is where signs of tunneling, C2, or data exfiltration appear.
- **Lateral Movement**: Tracking how threats pivot between internal stack layers.
    - Observing movement between layers helps identify attempts to move laterally in the network. Attackers often exploit multiple layers to reach sensitive assets.

#### **The Light Touch Approach**
- **Header Priority**: Focusing on Flags and Sequence Numbers to map the session.
    - Key header values tell you how the connection behaves without inspecting full payloads. This speeds up understanding of session dynamics.
- **Cognitive Optimization**: Filtering irrelevant layers early to reduce data noise.
    - Removing unnecessary information lets analysts focus on relevant traffic. It prevents fatigue and increases detection accuracy.
- **Protocol Scoping**: Isolating traffic by port and service before deep packet inspection.
    - Narrowing traffic by protocol ensures inspections are targeted. You don’t waste time digging into unrelated packets.

#### **Technical Mapping**
- **Encapsulation Check**: Verifying that data segments match expected protocol standards.
    - Each packet should conform to its protocol. Deviations can indicate crafted or malicious traffic.
- **Anomaly Detection**: Identifying non-standard behavior within specific stack levels.
    - Outliers at a particular layer often signal suspicious activity. This allows analysts to flag issues before they escalate.
- **Isolation Strategy**: Narrowing the scope of a hunt to a single layer of the stack.
    - Focusing on one layer at a time simplifies analysis and ensures no detail is overlooked. It’s a controlled approach for high-volume networks.

### Slide 4: Why We Filter
**Transforming the Firehose into Evidence**

#### **The Noise vs. Signal Problem**
- **Protocol Elimination**: Suppressing high-volume background noise like ARP, DHCP, and SSDP.
    - These protocols generate lots of packets but rarely carry threat indicators. Removing them helps analysts focus on meaningful traffic.
- **Service Filtering**: Masking local discovery traffic (LLMNR/NBNS) to reveal external intent.
    - Local discovery chatter can clutter logs. Filtering it out highlights suspicious interactions with external systems.
- **Resource Management**: Optimizing hardware performance by reducing the active packet set.
    - Less irrelevant traffic means faster analysis and reduced load on packet capture tools. It allows for more efficient investigation.

#### **Operational Benefits**
- **Artifact Velocity**: Drastically reducing the time to locate specific malicious indicators.
    - Quick identification of anomalies accelerates threat detection and response. Analysts can focus on the critical packets first.
- **Narrative Clarity**: Creating clean views that simplify complex attack chains.
    - Filtering out noise helps build a coherent story of the attack. It makes it easier to see the sequence of events.
- **Evidence Preservation**: Isolating relevant packets for streamlined reporting and documentation.
    - By separating only relevant data, you ensure accurate reporting and maintain a solid chain of evidence.

#### **Precision Analysis**
- **Dynamic Scoping**: Adjusting filters in real-time as the investigation pivots.
    - Analysts can refine their focus on emerging leads. Flexibility ensures nothing important is missed.
- **False Positive Reduction**: Hardening the dataset against common network chatter.
    - Filtering out predictable, benign traffic reduces distractions. This lowers the chance of chasing harmless anomalies.
- **Logic-Based Hunting**: Using Boolean operators to isolate specific session attributes.
    - Boolean logic allows precise targeting of queries, sources, destinations, and protocols. This ensures the results are highly relevant and actionable.

### Slide 5: TCP Filtering
**Analyzing Handshakes and Session State**

#### **Connection Integrity**
- **Handshake Validation**: Verifying successful three-way handshakes (SYN, SYN-ACK, ACK).
    - Confirming handshakes ensures the session was properly established. Failed or incomplete handshakes can indicate scanning, drops, or active interference.
- **Retransmission Analysis**: Identifying packet loss, latency, or potential interference.
    - Retransmissions reveal network reliability issues or possible malicious interruption attempts. It helps distinguish normal congestion from suspicious behavior.
- **State Tracking**: Monitoring the lifecycle of a session from establishment to teardown.
    - Following a session from start to finish provides context for anomalies. Analysts can see how connections progress and identify unexpected closures.
- **Flow Control**: Observing window size scaling and congestion notification.
    - Tracking flow control helps understand how data moves across the network. Abnormal scaling or repeated congestion events can hint at tampering or misconfiguration.

#### **Flag-Based Syntax**
- **`tcp.flags.syn == 1 and tcp.flags.ack == 0`**: Isolates initial connection attempts.
    - This filter highlights new sessions starting. It's useful for spotting unexpected outbound or inbound connection attempts.
- **`tcp.flags.reset == 1`**: Identifies abruptly terminated or refused connections.
    - RST flags signal that a session was forcefully closed, often indicating scanning, firewall blocking, or malicious termination.
- **`tcp.flags.fin == 1`**: Highlights graceful session closures.
    - FIN flags show that the connection ended normally. Comparing these to unexpected RSTs can highlight anomalies.
- **`tcp.flags.push == 1`**: Locates immediate data transfer bursts within a stream.
    - PSH flags indicate that data is being sent immediately, which can reveal exfiltration or sudden command execution.

#### **Performance & Error Logic**
- **`tcp.analysis.retransmission`**: Pinpoints network congestion or dropped packets.
    - Retransmissions are logged when packets fail to reach the destination. Frequent occurrences may indicate instability or targeted disruptions.
- **`tcp.analysis.zero_window`**: Detects receiver-side processing bottlenecks.
    - A zero-window condition shows the receiver can't accept more data. This can be normal or hint at a system under load or attack.
- **`tcp.analysis.lost_segment`**: Maps gaps in the sequence number stream.
    - Missing segments highlight packet loss or interception. Tracking these gaps helps validate the integrity of the session and identify potential tampering.

### Slide 6: UDP & DNS
**Investigating Connectionless Traffic and Name Resolution**

#### **DNS Forensic Artifacts**
- **Outbound Queries**: Tracking dns.flags.response == 0 to audit internal host requests.
    - Monitoring outgoing DNS queries shows what internal hosts are trying to resolve. Unexpected or high-volume queries can reveal scanning or exfiltration attempts.
- **High-Entropy Subdomains**: Identifying randomized strings that signal encoded data transfer.
    - Subdomains with random-looking characters often carry hidden payloads. This is a common method for malware to sneak data out.
- **C2 Communication**: Spotting TXT records used as vessels for remote commands.
    - TXT records can hide encoded instructions. Malware regularly checks these to get tasks without raising alarms.
- **Response Analysis**: Monitoring for NXDOMAIN spikes indicative of subdomain brute-forcing.
    - Sudden bursts of unresolved domains signal automated enumeration. This helps identify reconnaissance activity before attacks escalate.

#### **UDP Syntax & Identification**
- **Non-Standard Traffic**: `udp.port != 53 and udp.port != 123` to isolate atypical UDP behavior.
    - Filtering out normal DNS and NTP traffic lets analysts focus on unusual UDP flows. These can reveal hidden channels or attack traffic.
- **String Complexity**: `dns.qry.name.len > 20` to catch unusually long, suspicious domains.
    - Long query names often carry encoded or tunneled data. Flagging them quickly isolates potential threats.
- **Tunneling Detection**: Identifying `dns.count.labels > 4` for deeply nested, tunneled traffic.
    - Deep subdomain hierarchies are rarely legitimate. They often indicate automated DNS tunneling or beaconing.
- **Payload Inspection**: Filtering for `dns.txt > 100` to find large, script-heavy records.
    - Large TXT responses are unusual in normal operations. They’re often used to smuggle commands or data into the network.

#### **Operational Context**
- **Stateless Risk**: Managing the lack of handshake verification in connectionless protocols.
    - UDP doesn’t confirm delivery or order, making detection trickier. Analysts must consider this when interpreting anomalies.
- **Vessel Activity**: Recognizing DNS as a high-trust protocol often ignored by firewalls.
    - Attackers exploit DNS because it is trusted and rarely blocked. Monitoring it closely is key to catching covert activity.
- **Data Exfiltration**: Visualizing how small, fragmented packets bypass volume-based alerts.
    - Exfiltrated data is split into many tiny queries to evade detection. Pattern recognition over time reveals the theft.

### Slide 7: HTTP/S Analysis
**Analyzing Web Traffic and Encrypted Indicators**

#### **Application Layer Indicators**
- **Data Submission**: `http.request.method == "POST"` to audit outbound data transfers.
    - POST requests often carry more than user input; they can be a channel for exfiltrating files. Monitoring them helps catch abnormal uploads.
- **User-Agent Analysis**: Identifying automated tools like curl, powershell, or python-requests.
    - Unexpected user-agent strings can signal scripts or malware rather than legitimate browsers. This is a subtle but effective detection method.
- **Path Investigation**: Monitoring for suspicious URI strings and unauthorized file access.
    - Malicious actors often target hidden directories or attempt uploads/downloads in unusual locations. Tracking paths reveals these attempts.
- **Response Codes**: Tracking 403 Forbidden or 404 Not Found for directory brute-forcing.
    - Patterns of denied or missing resource responses often indicate scanning or brute-force probing. They’re key indicators of reconnaissance.

#### **Encrypted Traffic Visibility**
- **Domain Identification**: `tls.handshake.extensions_server_name` to extract the target via SNI.
    - SNI allows identification of the requested domain even within encrypted sessions. This is crucial for detecting connections to suspicious or malicious endpoints.
- **Certificate Validation**: Detecting self-signed certificates or anomalous issuer names.
    - Unusual certificates may indicate man-in-the-middle attacks or connections to attacker-controlled servers. Analysts should flag these deviations.
- **Protocol Hygiene**: Identifying legacy TLS 1.0/1.1 versions and weak cipher suites.
    - Older protocols are both vulnerable and often indicative of misconfigured or malicious clients. Monitoring for them improves security posture.
- **Fingerprinting**: Utilizing JA3 hashes to identify specific client-side malware signatures.
    - JA3 fingerprints provide a unique signature for TLS clients. Matching them against known malware profiles helps quickly identify infected systems.

#### **Secure Channel Analysis**
- **Handshake Integrity**: Verifying the Client Hello and Server Hello exchange.
    - Ensuring a proper handshake confirms that connections are authentic. Deviations can signal interception or malware activity.
- **Certificate Pinning**: Spotting discrepancies in expected vs. presented public keys.
    - Unexpected certificate changes indicate potential MITM attacks or traffic rerouting. This is an advanced way to detect tampering.
- **Traffic Entropy**: Distinguishing between standard encrypted web traffic and tunneled C2.
    - High-entropy patterns in otherwise normal HTTPS flows can reveal covert channels. This analysis helps uncover hidden exfiltration or C2 communication.

### Slide 8: Combining Filters
**Surgical Navigation via Boolean Logic**

#### **Logical Operators**
- **AND Usage**: Narrowing results to specific, intersecting criteria.
    - Using AND ensures that only packets meeting all selected conditions appear. This is key for pinpointing precise malicious activity.
- **OR Usage**: Expanding results to include multiple distinct possibilities.
    - OR lets you capture multiple scenarios in a single search. It's useful when threats may manifest in different but related ways.
- **NOT Usage**: Excluding known-safe traffic (such as `not arp` or `not ssl`).
    - NOT removes irrelevant or benign traffic, reducing noise and focusing attention on unusual activity.
- **Nesting**: Using parentheses to prioritize complex logical evaluations.
    - Nesting allows combining operators in a controlled order. This helps construct precise filters for multi-faceted investigations.

#### **Precision Example**
- **Target Isolation**: `ip.addr == [Target] and not tcp.port == 443`
    - This isolates activity for a specific host while ignoring normal HTTPS traffic. It’s a practical way to focus on anomalies.
- **Exclusion Logic**: Removing noise to reveal non-standard protocol usage.
    - By filtering out expected traffic, subtle malicious behaviors become visible. Analysts can quickly see patterns that would otherwise be hidden.
- **Refined Scope**: Combining IP, port, and flag filters for surgical accuracy.
    - Layering multiple criteria ensures the results are highly targeted. This reduces false positives and highlights relevant packets.

#### **Operational Workflow**
- **Noise Reduction**: Progressively stripping away authorized traffic layers.
    - Start broad, then remove normal traffic step by step. This approach systematically uncovers hidden threats.
- **Pivot Discovery**: Using inclusive logic to follow an attacker across ports.
    - Inclusive filters help track an attacker as they move laterally or change tactics. You can see the full trajectory of their activity.
- **Result Validation**: Testing filter strings to ensure critical data is not eclipsed.
    - Always verify that the filters don’t inadvertently hide important packets. Validation preserves the integrity of the investigation.

---

## 2. Conversation Analysis
This section focuses on stepping back from individual packets and looking at the bigger picture of network communication. It shows how to group traffic into conversations so you can quickly identify which hosts are talking, how much data is being transferred, and whether the behavior looks normal or suspicious. From there, it digs into evaluating endpoints by spotting top talkers, unusual external connections, and signs of lateral movement inside the network. It also covers how to use protocol hierarchy to validate whether traffic distribution makes sense, helping you catch mismatches, unauthorized protocols, or hidden tunnels. Overall, the goal is to turn raw traffic into a clear view of relationships, risks, and potential attack paths across the network.

### Slide 9: The Big Picture
**Visualizing Host-to-Host Relationships**

#### **The Conversations Window**
- **Aggregation Strategy**: Navigating to `Statistics > Conversations` for session-level data.
    - This view condenses individual packets into summarized conversations. It’s the first step to understanding who is talking to whom across the network.
- **Logical Grouping**: Consolidating thousands of individual packets into distinct, readable flows.
    - Grouping packets by host, protocol, or port turns a messy capture into a clear narrative. Analysts can quickly see which connections are relevant.
- **Protocol Scoping**: Sorting by Ethernet, IP, TCP, or UDP to isolate the attack vector.
    - Filtering by protocol helps focus on the layer most likely carrying malicious activity. It narrows down the search from broad network chatter to actionable data.
- **Efficient Mapping**: Visualizing the entire network landscape from a single management view.
    - A holistic perspective allows analysts to spot patterns and relationships that would be invisible when examining packets individually.

#### **Top-Level Metrics**
- **Host Identification**: Determining the primary talkers (Internal vs. External endpoints).
    - Recognizing which hosts generate the most traffic can pinpoint potential attackers or compromised systems. It’s also helpful for prioritizing investigations.
- **Data Volume**: Evaluating Byte Count to identify potential exfiltration or heavy downloads.
    - Large amounts of outbound data can indicate exfiltration. High inbound traffic might reveal malware payloads or downloads.
- **Temporal Analysis**: Analyzing session duration to distinguish brief scans from persistent links.
    - Short-lived sessions often indicate reconnaissance. Longer sessions may signify established C2 channels or data transfers.
- **Packet Symmetry**: Comparing sent vs. received counts to identify Push or Pull behavior.
    - Imbalances can show whether a host is primarily sending commands, exfiltrating data, or being used as a passive receiver.

#### **Forensic Significance**
- **Outlier Detection**: Spotting high-bandwidth sessions that deviate from established baselines.
    - Anything that stands out against the normal patterns warrants deeper inspection. Baseline comparisons are crucial for early threat detection.
- **Geographic Triage**: Checking external IP ownership for unauthorized or high-risk regions.
    - Mapping IPs to locations or ASNs can reveal unexpected international connections. This helps focus response efforts on suspicious regions.
- **Infection Tracking**: Identifying Patient Zero by tracing the earliest timestamped flows.
    - Determining the first host involved provides a starting point for remediation. It also helps reconstruct the attack timeline accurately.

### Slide 10: Endpoint Evaluation
**Identifying Top Talkers and Asset Risk**

#### **Internal vs. External Mapping**
- **Infrastructure Attribution**: Tracking connections to known VPS providers like DigitalOcean, AWS, or Linode.
    - Connections to cloud services can be legitimate or suspicious. Correlating them with known malicious infrastructure helps prioritize alerts.
- **Service Exposure**: Auditing internal hosts reaching out via Port 445 (SMB) or Port 3389 (RDP).
    - Unexpected outbound administrative traffic may indicate compromised machines or lateral movement attempts. Monitoring these ports is essential for early detection.
- **Geographic Triage**: Identifying traffic bound for high-risk or unexpected international IP ranges.
    - Cross-border connections to unfamiliar regions often require closer inspection. They can be indicative of data exfiltration or remote control activity.
- **Beacon Identification**: Spotting persistent, low-volume connections to external command nodes.
    - Even small, regular communication bursts can signal C2 beaconing. Detecting these requires time-series analysis rather than packet volume alone.

#### **Lateral Movement Artifacts**
- **Administrative Spikes**: Monitoring high volumes of internal-to-internal SMB or RPC traffic.
    - Sudden surges in internal administrative traffic may indicate propagation of malware or active reconnaissance.
- **Peer-to-Peer Anomalies**: Flagging workstations communicating directly with other workstations.
    - Unusual workstation-to-workstation communication often signals unauthorized lateral movement or rogue activity.
- **Credential Hopping**: Identifying repeated authentication attempts across multiple internal assets.
    - Multiple failed or successful login attempts can reveal compromised credentials being tested across the network.
- **Protocol Misuse**: Detecting non-standard administrative tools moving through the local network.
    - Attackers often repurpose legitimate tools in unusual ways. Tracking deviations from normal administrative traffic highlights potential misuse.

#### **Asset Risk Profiling**
- **Criticality Assessment**: Prioritizing investigations based on the sensitivity of the involved internal host.
    - High-value assets require more attention. Their compromise could have larger organizational impact.
- **Baselines**: Comparing current endpoint behavior against historical Normal traffic patterns.
    - Deviations from baseline behavior are often the first signal of compromise. This context is essential for meaningful alerts.
- **Blast Radius**: Visualizing how many internal systems a compromised host has touched.
    - Understanding the extent of exposure helps guide containment and remediation efforts. It also informs risk management and response prioritization.

### Slide 11: Protocol Hierarchy
**Validating Traffic Distribution vs. Network Baseline**

#### **Visualizing the Mix**
- **Hierarchical Mapping**: Navigating to `Statistics > Protocol Hierarchy` for a top-down view of the capture.
    - This view organizes all traffic by protocol and sub-protocol, making it easy to see the overall network composition. It helps analysts identify unusual activity quickly.
- **Percentage Distribution**: Evaluating the ratio of TCP vs. UDP to establish a behavioral baseline.
    - Comparing expected vs. observed ratios helps flag anomalies. Deviations can indicate tunneling, malware, or misconfigurations.
- **Unauthorized Discovery**: Identifying non-business protocols like IRC, BitTorrent, or Tor.
    - Unexpected protocols often signal covert communication channels or policy violations. Spotting them early reduces risk exposure.
- **Sub-Protocol Auditing**: Drilling down into specific application layers to find hidden payloads.
    - Examining sub-protocol traffic can reveal malware or tunneling hidden under normal-looking protocols. This is critical for catching subtle threats.

#### **Protocol Mismatch Detection**
- **Anomalous Ports**: Spotting cleartext Telnet or HTTP behavior masquerading over Port 443.
    - Protocols running on non-standard ports often indicate evasion or malicious activity. This mismatch is a red flag for deeper inspection.
- **Encapsulation Errors**: Identifying non-DNS traffic attempting to egress via Port 53.
    - Non-DNS traffic on DNS ports can signal tunneling or exfiltration attempts. Analysts should verify each anomaly against expected traffic.
- **Service Validation**: Verifying that the protocol structure matches the assigned port designation.
    - Ensuring alignment between protocol and port assignment confirms traffic legitimacy. Mismatches often indicate misuse or attack attempts.
- **Tunnels and Wrappers**: Detecting SSH or VPN signatures inside standard web traffic streams.
    - Malicious actors often hide encrypted tunnels within normal web traffic. Detecting these wrappers helps uncover covert communication.

---

## 3. Identifying Abnormal Flows
This section is all about recognizing what normal looks like so abnormal behavior stands out quickly and clearly. It explains how baselining things like traffic patterns, user behavior, and protocol usage gives you a reference point to catch deviations such as after-hours activity or new external connections. From there, it breaks down different types of traffic flows, comparing high-volume “elephant” flows that may indicate large data transfers with low-and-slow “mice” flows that often point to command and control activity. It also covers common reconnaissance patterns like port scanning and shows how timing, packet behavior, and response types reveal probing activity. Finally, it brings in geolocation analysis to add context, helping you identify suspicious connections based on where traffic is coming from or going to, and tying that back to overall risk and potential attacker behavior.

### Slide 12: Defining Normal
**The Necessity of the Baseline**

#### **Network Identity**
- **Temporal Patterns**: Documenting expected business-hour spikes to separate commerce from compromise.
    - Knowing typical traffic cycles helps distinguish normal peaks from suspicious surges. This baseline is critical for spotting abnormal activity.
- **Authorized Assets**: Mapping known Service Accounts and administrative IP ranges.
    - Identifying trusted endpoints and accounts allows analysts to quickly flag unknown actors. This reduces the time spent chasing false positives.
- **Protocol Whitelisting**: Establishing a Golden Image of standard application traffic.
    - Defining acceptable protocols ensures that any deviation is immediately suspicious. It creates a reference for anomaly detection.
- **User Behavior**: Identifying the typical volume and destination of standard department workflows.
    - Understanding normal patterns by department or role helps detect abnormal activity at the user level.

#### **Anomalous Timing**
- **Temporal Shifting**: Identifying after-hours data bursts that suggest automated exfiltration.
    - Out-of-hours activity often points to scheduled malware or stealthy exfiltration. Monitoring timing is as important as monitoring volume.
- **Unauthorized Flows**: Spotting new, internal-to-internal connections during low-staffing periods.
    - Unexpected internal traffic may indicate lateral movement or rogue processes. Timing helps differentiate benign operations from attacks.
- **Execution Windows**: Correlating network spikes with scheduled tasks vs. manual attacker activity.
    - Understanding when automated tasks run helps avoid false positives and highlights true anomalies.

#### **Deviation Analysis**
- **Volume Thresholds**: Setting alerts for byte counts that exceed the historical daily average.
    - Large deviations from normal volume often indicate exfiltration or abnormal downloads. Thresholds help prioritize investigations.
- **New Endpoint Discovery**: Flagging the first appearance of an external IP within the environment.
    - A previously unseen external host may be malicious. Early detection reduces response time.
- **Ratio Shifts**: Monitoring for sudden changes in the Upload-to-Download balance.
    - An unusual upload/download ratio can signal data leaving the environment. This is a subtle but powerful indicator of compromise.

### Slide 13: Elephant vs. Mice Flows
**Volume Analysis for Threat Detection**

#### **Elephant Flows (Volume-Based)**
- **Massive Transfers**: Identifying sustained, high-bandwidth outbound flows on FTP, SFTP, or HTTPS.
    - Large data transfers often indicate exfiltration or bulk staging of files. These are the elephants in network traffic that demand immediate attention.
- **Exfiltration Risk**: Spotting large-scale data staging or theft in progress.
    - Monitoring sustained high-volume transfers helps catch major breaches before they complete.
- **Network Impact**: Detecting saturation that degrades service for legitimate traffic.
    - High-volume flows can slow down business operations. Recognizing them early ensures both security and operational continuity.
- **Symmetry Check**: Monitoring for high Push ratios with minimal inbound responses.
    - Asymmetrical traffic often signals one-way data movement. This can reveal exfiltration or unidirectional command channels.

#### **Mice Flows (Frequency-Based)**
- **C2 Heartbeats**: Detecting sustained, low-volume packets with minimal or empty payloads.
    - Small but frequent packets may indicate command-and-control communications. They are subtle and easy to miss without proper analysis.
- **Keep-alives**: Identifying persistent connections designed to bypass firewall timeouts.
    - These ensure continuous access for attackers while avoiding detection. Monitoring timing patterns is crucial.
- **Low-and-Slow**: Recognizing automated queries that evade volume-based detection thresholds.
    - Gradual, minimal activity avoids raising immediate alarms. Analysts must rely on pattern recognition rather than volume spikes.
- **Consistency**: Analyzing Time-Series patterns for lack of human-generated jitter.
    - Perfectly timed, repetitive queries are usually machine-driven, a strong indicator of malware.

#### **Analytical Differentiation**
- **Volume vs. Velocity**: Distinguishing between a single large Heist and constant Whispers.
    - This separation helps prioritize response: elephants are urgent and obvious, mice are subtle and persistent.
- **Triage Strategy**: Prioritizing investigations based on the immediate impact to data integrity.
    - Understanding the threat’s scale guides how quickly and aggressively it should be mitigated.
- **Signature Mapping**: Matching flow characteristics to known malware communication profiles.
    - Comparing traffic patterns to historical threat behaviors improves detection and reduces investigation time.

### Slide 14: Port Scanning Patterns
**Recognizing Reconnaissance Signatures**

#### **Scan Types**
- **Vertical Scan**: A single source IP probing multiple ports on a specific host to find vulnerabilities.
    - This type of scan focuses on one target and tests many services. It’s a common early stage of attack to map open entry points.
- **Horizontal Sweep**: A single source IP targeting one specific port across an entire subnet.
    - These scans look for common services across multiple hosts. They’re often used to find weakly protected machines en masse.
- **Strobe Scan**: Focusing on a small set of known-vulnerable ports across multiple systems.
    - By limiting the number of ports tested, attackers can reduce noise and avoid detection while still identifying exploitable hosts.
- **Target Mapping**: Identifying the inventory phase before an exploit is launched.
    - Scans are essentially reconnaissance. They help attackers understand the network landscape before moving to exploitation.

#### **Forensic Artifacts**
- **Port Unreachable**: Monitoring for ICMP Type 3, Code 3 responses from the target host.
    - These responses indicate that the port is closed. High volumes can reveal the presence of systematic scanning.
- **SYN-Stealth Signatures**: Identifying half-open connections that never complete the handshake.
    - SYN scans avoid full connection establishment to remain stealthy. Analysts can detect these through incomplete handshakes.
- **Reset Spikes**: Tracking high volumes of RST packets in response to closed-port probes.
    - Sudden bursts of RST packets often correspond to scanning activity. They provide strong evidence of reconnaissance attempts.
- **Sequence Timing**: Detecting rapid-fire query intervals that lack human-like delay.
    - Automated scanning is usually faster and more regular than human activity. Timing analysis can reveal this pattern.

#### **Defensive Context**
- **Triage Priority**: Distinguishing between internet background noise and targeted internal scans.
    - Not all scans are malicious. Analysts need to separate random internet probes from focused attacks.
- **Honeypot Hits**: Identifying probes against non-existent or high-value internal decoy assets.
    - Honeypots act as early-warning systems. Hits here indicate active reconnaissance targeting your environment.
- **Scanning Direction**: Determining if the scan is originating from an external actor or a compromised internal host.
    - Knowing the source of the scan helps in response planning. Internal origins often suggest a compromised system or insider threat.

### Slide 15: Geolocation Anomalies
**Mapping IP Addresses to Physical Locations**

#### **Contextual Analysis**
- **Business Presence**: Flagging traffic to regions where the organization has no employees or customers.
    - Connections to unexpected regions often indicate suspicious activity. Analysts can prioritize these for further investigation.
- **Database Integration**: Utilizing MaxMind or IPinfo for real-time geographic insights.
    - Geo-IP databases provide actionable context for network traffic. They help identify unusual destinations or origins quickly.
- **Policy Alignment**: Correlating traffic destinations with corporate Geofencing restrictions.
    - Comparing traffic to internal policies ensures adherence to geographic access controls. Deviations may signal policy violations or compromise.
- **Travel Profiling**: Comparing user login locations against known employee travel itineraries.
    - This helps detect anomalies like impossible travel or account compromise. Legitimate user movement is validated against expected patterns.

#### **Risk Assessment**
- **Host Reputation**: Investigating traffic to jurisdictions known for Bulletproof hosting.
    - Certain regions are hotspots for malicious infrastructure. Connections here are inherently higher risk and deserve attention.
- **VPN/Proxy Detection**: Identifying exit nodes used to mask an attacker's true origin.
    - VPNs and proxies can hide malicious activity. Recognizing these helps contextualize anomalous IPs.
- **Data Sovereignty**: Monitoring for unauthorized data movement across international borders.
    - Unapproved cross-border traffic may violate compliance rules and indicate exfiltration. This is a key control for sensitive information.
- **High-Risk Zones**: Prioritizing alerts for connections originating from sanctioned or high-threat regions.
    - Alerts from these zones require immediate review. They often correlate with advanced persistent threat activity.

#### **Forensic Significance**
- **Impossible Travel**: Detecting logins from two distant locations within a physically impossible timeframe.
    - This strongly suggests account compromise. Identifying such patterns early can prevent further exploitation.
- **Inbound Spikes**: Tracking sudden increases in unsolicited traffic from a specific country code.
    - Sudden bursts may indicate scanning, reconnaissance, or attack campaigns originating from that region.
- **Exfiltration Paths**: Mapping the final destination of stolen data packets for attribution.
    - Understanding where data ends up is critical for both mitigation and legal reporting. It also informs long-term defensive adjustments.

---

## 4. Recognizing Beacon Intervals
This section focuses on identifying beaconing behavior, which is a key indicator of malware maintaining communication with a command and control server. It explains how compromised systems regularly “check in” at consistent intervals, often blending into normal traffic like HTTPS or DNS, and how these patterns differ from natural human activity. It then shows how to analyze timing using tools like time-delta measurements and graphs to spot consistent intervals or clustered traffic patterns. The section also highlights how attackers use jitter to slightly randomize timing and avoid simple detection, while still leaving behind statistically detectable patterns. Finally, it introduces tools and automation that help scale this analysis, making it possible to detect persistent, low-and-slow beaconing across large networks.

### Slide 16: What is a Beacon?
**Malware Command & Control (C2) Persistence**

#### **The C2 Heartbeat**
- **Automated Check-ins**: Periodic connections to a remote server to retrieve new instructions.
    - These recurring communications are how malware stays in contact with its operator. Each connection often retrieves new tasks or confirms status.
- **Protocol Blending**: Disguising malicious traffic within standard HTTPS or DNS streams.
    - By hiding in normal protocols, beacon traffic avoids triggering traditional firewall or IDS alerts. It looks "normal" at a glance.
- **Instruction Retrieval**: Pulling down shell commands, scripts, or additional payloads.
    - Every beacon carries instructions, often in encoded form, allowing the attacker to control the host without direct access.
- **Persistence**: Maintaining a foothold even after system reboots or network changes.
    - Beacons ensure the malware remains active long-term. They are the lifeline between attacker and compromised system.

#### **User vs Machine**
- **Mechanical Regularity**: Identifying exact, repeating intervals (such as every 5 minutes) that signal a script.
    - Regular, perfectly timed intervals are rarely human. This mechanical rhythm is a hallmark of automated C2.
- **Human Jitter**: Distinguishing sporadic browsing habits from automated software patterns.
    - Human activity is irregular; machines are predictable. Comparing timing helps separate legitimate traffic from malicious automation.
- **Temporal Entropy**: Measuring the randomness of connection times to find hidden automation.
    - Low entropy in timing often indicates machine-driven activity. High entropy would suggest genuine user behavior.
- **Payload Consistency**: Spotting identical request sizes that suggest a programmed Keep-alive.
    - Identical payloads across intervals are a signature of automated beaconing rather than varied human-generated traffic.

#### **Detection Markers**
- **Long-Tail Analysis**: Reviewing 24-hour captures to find connections that never stop.
    - Beacons may be subtle in short time slices. Observing longer windows reveals persistent patterns.
- **Domain Reputation**: Checking if the beaconing endpoint is a newly registered domain (NRD).
    - Newly created domains are often associated with malware infrastructure. Correlating domains helps validate suspicion.
- **Header Staticity**: Finding identical User-Agents and Cookie strings across every request.
    - Consistent headers are unusual for normal users. This repetition provides a reliable detection signal.

### Slide 17: Visualizing Timing
**Time-Delta Analysis**

#### **Syntax & Setup**
- **Column Configuration**: Adding `frame.time_delta_displayed` to the packet list for precision.
    - This column shows the exact time between packets, which is essential for detecting automated activity. Analysts can immediately spot unusually regular intervals.
- **Perfect Periodicity**: Finding packets spaced by exactly 60.000s or other fixed intervals.
    - Malware often generates perfectly timed requests. These exact intervals rarely occur naturally in user behavior.
- **Precision Tracking**: Measuring the microsecond differences between related request packets.
    - Tiny timing discrepancies can reveal attempts to obfuscate automation. Microsecond-level analysis uncovers subtle manipulation.
- **Filtering Logic**: Isolating specific streams to calculate the gap between C2 check-ins.
    - Focusing on individual connections allows you to quantify timing consistency and detect hidden beacons.

#### **Graphical Analysis**
- **IO Graphs**: Navigating to `Statistics > IO Graphs` to map packet frequency over time.
    - Graphs provide a visual timeline of network activity, making patterns easier to recognize than raw packet lists.
- **Interval Clumping**: Visualizing bursts of traffic occurring at predictable, fixed cycles.
    - Consistent clusters of packets are a hallmark of automated processes. Clumping helps separate these from human traffic.
- **Jitter Evaluation**: Identifying intentional delays added by malware to mimic human noise.
    - Some malware adds minor variability to hide in plain sight. Measuring jitter reveals attempts at stealth.
- **Baseline Overlay**: Comparing suspicious timing against known, legitimate system updates.
    - Overlaying normal behavior helps differentiate between acceptable automated processes and potential malware activity.

### Slide 18: The Jitter Factor
**Evading Simple Detection via Randomness**

#### **Timing Variance**
- **Jitter Definition**: Randomly adding or subtracting time to break a perfectly fixed interval.
    - Malware introduces slight randomness to hide predictable patterns. This makes automated detection less effective.
- **The ±20% Window**: Hiding the C2 heartbeat within a variable time range to mimic human unpredictability.
    - Small deviations create the illusion of normal user behavior while maintaining a regular automated schedule.
- **Evasion Strategy**: Defeating simple automated alerts that only flag exact periodicity (such as `60.000s`).
    - Attackers know that basic monitoring looks for perfect intervals, so jitter prevents easy detection.
- **Pattern Masking**: Blending malicious check-ins with the organic noise of standard web browsing.
    - By mixing with normal activity, beacons become less distinguishable from legitimate traffic.

#### **Mathematical Detection**
- **Average Intervals**: Calculating the mean time-delta to identify a baseline frequency despite the jitter.
    - Even with randomness, average intervals reveal the underlying automation. This helps analysts detect stealthy beacons.
- **Cluster Analysis**: Grouping packets by destination to see if clumps still occur within a specific window.
    - Traffic may still cluster around repeated targets, exposing hidden patterns despite jitter.
- **Long-Tail Observation**: Monitoring traffic over 24-48 hours to reveal the persistent underlying script.
    - Extended monitoring makes it easier to separate machine-driven activity from human variability.
- **Standard Deviation**: Using math to prove that the randomness is still too consistent for a human user.
    - Statistical methods quantify irregularity and highlight patterns that are unnatural for real users.

### Slide 19: Tools for Beacon Detection
**Automation Beyond Manual Analysis**

#### **Statistical Tools**
- **RITA (Real Intelligence Threat Analytics)**: Open-source framework for detecting C2 through beaconing and long-duration connections.
    - RITA automates the identification of low-and-slow malware activity. It highlights hosts that maintain persistent, periodic communication.
- **Interval Tagging**: Utilizing specialized Wireshark Lua scripts to automate the calculation of time-deltas across large pcaps.
    - Scripts save analysts time by quickly flagging potential beacon patterns without manually checking every packet.
- **Score-Based Analysis**: Applying mathematical models to rank connections based on their likelihood of being automated.
    - By scoring connections, analysts can prioritize the most suspicious traffic and reduce false positives.
- **Open Source Ecosystem**: Leveraging community-driven tools to augment manual packet inspection.
    - Open-source tools provide flexibility and allow rapid adoption of new detection methods from the research community.

#### **Enterprise Integration**
- **Zeek (Formerly Bro)**: Utilizing high-level network logs for long-term pattern identification without the overhead of full packet captures.
    - Zeek enables scalable monitoring across the enterprise, giving insight into repeated patterns that might otherwise be missed.
- **SIEM Correlation**: Exporting metadata to platforms like Splunk or ELK for cross-protocol behavior analysis.
    - Centralizing logs allows detection across multiple vectors, connecting DNS, HTTP/S, and endpoint activity for richer context.
- **Fleet Visibility**: Monitoring thousands of endpoints simultaneously to find Top Talkers in real-time.
    - This ensures that persistent C2 activity is caught quickly, even in large, distributed networks.
- **Data Retention**: Analyzing trends over weeks or months to catch Low-and-Slow actors that evade short-term windows.
    - Historical analysis uncovers stealthy malware that avoids triggering short-term alerts, providing a more complete threat picture.

---

## 5. Pattern Recognition Discipline
This section focuses on the mindset and discipline required to be an effective analyst, emphasizing that strong investigations are built on evidence, not assumptions. It highlights the importance of staying objective, avoiding bias, and validating findings through multiple sources while maintaining clear, reproducible documentation. It also connects technical discoveries to frameworks like MITRE ATT&CK, showing how to translate packet-level analysis into meaningful reports and defensive improvements. The section wraps everything together by reinforcing a structured workflow from filtering to documentation, while encouraging continuous practice, knowledge sharing, and deeper tool proficiency to keep improving over time.

### Slide 20: The Analyst's Mindset
**Objectivity and Evidence-Based Logic**

#### **Discipline over Hunch**
- **Data-Driven Narratives**: Letting the packets tell the story rather than forcing a preconceived theory.
    - Analysts focus on what the traffic reveals instead of jumping to assumptions. Every finding is backed by observable evidence.
- **Bias Mitigation**: Actively avoiding Confirmation Bias by seeking evidence that disproves your own hypothesis.
    - Challenging your initial thoughts ensures the investigation isn’t skewed. True patterns emerge when you test assumptions rigorously.
- **The Zero Trust Lens**: Treating every internal host as a potential threat until the traffic proves otherwise.
    - Even trusted machines are scrutinized. This mindset prevents blind spots in monitoring.
- **Rigorous Validation**: Cross-referencing findings across multiple tools (such as Wireshark vs. Zeek logs).
    - Consistency across different platforms strengthens conclusions and ensures nothing is missed.

#### **The Investigation Trail**
- **Analyst Notebooks**: Maintaining a chronological log of applied filters, timestamps, and specific packet numbers.
    - Detailed notes help reconstruct the investigation and allow others to follow your logic step by step.
- **Reproducibility**: Ensuring that another analyst can apply your filter strings and reach the same conclusion.
    - Sharing reproducible steps increases reliability and supports collaboration in the SOC.
- **Documentation Hygiene**: Capturing screenshots and exporting specific packet ranges for evidence preservation.
    - Clean documentation allows findings to be presented clearly to management or legal teams.
- **Knowledge Transfer**: Building a library of successful hunt queries to share with the wider SOC team.
    - Over time, this creates a resource that accelerates future investigations and improves overall team proficiency.

### Slide 21: Documentation & Mapping
**Aligning Evidence to Defensive Frameworks**

#### **MITRE ATT&CK Correlation**
- **T1071 (Application Layer Protocol)**: Identifying malware using standard protocols (HTTP/DNS) to blend with web traffic.
    - Mapping C2 traffic to T1071 helps analysts show how attackers exploit normal network behaviors to stay hidden.
- **T1041 (Exfiltration Over C2 Channel)**: Mapping high-volume outbound Elephant flows to stolen data transfers.
    - Correlating exfiltration flows to ATT&CK techniques provides context for prioritizing response efforts.
- **T1046 (Network Service Scanning)**: Cataloging reconnaissance signatures like horizontal sweeps or vertical port scans.
    - Documenting scanning patterns ensures that reconnaissance activity is linked to potential follow-on attacks.
- **T1571 (Non-Standard Port)**: Documenting protocols operating outside of their assigned port designations.
    - Noting unusual port usage highlights attempts to bypass standard monitoring and can indicate stealthy operations.

#### **Reporting Artifacts**
- **File Integrity**: Including the SHA256 hash of the original PCAP to ensure evidence remains untampered.
    - Hashes provide verifiable proof that the raw capture hasn’t been altered during analysis or reporting.
- **Precision Referencing**: Documenting specific Frame Numbers for every critical packet cited in the report.
    - Exact references allow peers or auditors to quickly locate the packet in question for validation.
- **Evidence Export**: Attaching exported .pcapng snippets containing only the relevant malicious streams.
    - Sharing isolated captures keeps reports concise and prevents unnecessary exposure of unrelated traffic.
- **Filter Transparency**: Listing the exact Wireshark display filters used to reach the reported conclusions.
    - Clearly stating filters ensures reproducibility and maintains credibility in investigative reporting.

#### **Defensive Posture**
- **Control Validation**: Using packet data to prove if existing firewalls or EDRs successfully blocked an action.
    - This confirms whether your preventive measures are actually effective, giving confidence in your network defenses.
- **Gap Analysis**: Identifying Blind Spots where logging or inspection failed to catch a specific technique.
    - Finding these gaps helps pinpoint where attackers could operate unnoticed, guiding targeted improvements.
- **Continuous Improvement**: Feeding captured signatures back into the SIEM for future automated alerting.
    - Integrating new patterns ensures the security stack adapts and becomes smarter over time, reducing response latency for similar threats.

### Slide 22: Summary & Resources
**The 5-Step Process Review**

#### **The Pillars**
- **Filter**: Systematically reducing millions of packets into a manageable, targeted dataset.
    - Filtering turns the raw firehose into actionable information, letting you focus only on relevant flows.
- **Analyze**: Evaluating protocol behavior, timing, and session integrity for anomalies.
    - Understanding the details of each connection reveals hidden patterns that point to suspicious activity.
- **Identify**: Pinpointing Top Talkers, internal risks, and compromised assets.
    - Knowing which hosts stand out helps prioritize investigations and respond quickly to potential threats.
- **Recognize**: Mapping patterns like Beaconing, Port Scanning, and Data Exfiltration.
    - Detecting these behaviors signals active attacker presence and helps differentiate between low- and high-risk activity.
- **Document**: Translating technical findings into evidence-based, framework-aligned reports.
    - Proper documentation ensures the investigation is reproducible, actionable, and tied to recognized defensive frameworks.

#### **Learning Resources**
- **Interactive Labs & Training**:
    - TryHackMe: https://tryhackme.com/hacktivities/search?page=1&kind=all&searchText=wireshark&order=relevance  
    - Labex: https://labex.io/learn/wireshark  
    - LetsDefend (Installing Wireshark): https://app.letsdefend.io/training/lesson_detail/installing-the-wireshark  
    - LetsDefend (HTTP Basic Auth): https://app.letsdefend.io/challenge/http-basic-auth  
    - BlueTeamLabs.online (Piggy): https://blueteamlabs.online/home/investigation/piggy-aij2bd8h2  

#### **Expert Video & Documentation**
- **Chris Greer (Packet Analysis Playlist)**: https://www.youtube.com/playlist?list=PLW8bTPfXNGdA_TprronpuNh7Ei8imYppX  
- **Wireshark User Guide**: https://www.wireshark.org/docs/wsug_html_chunked/  

#### **The Analyst's Path**
- **Continuous Practice**: Regularly analyzing Normal traffic to sharpen your eye for the Abnormal.
    - Repetition builds intuition, letting you spot anomalies faster over time.
- **Community Engagement**: Sharing findings on Skool or LinkedIn to refine your defensive logic and receive feedback.
    - Engaging with peers exposes you to different investigative approaches and strengthens your skillset.
- **Tool Fluency**: Moving beyond basic filters into advanced statistics, IO graphing, and Lua scripting.
    - Mastering these capabilities allows you to automate repetitive analysis and uncover deeper, subtler patterns.

---

## 6. Practical Quiz
This quiz walks through a full TrickBot “rob13” infection capture, guiding you step by step through identifying the initial compromise, mapping host information, and tracking malware behavior. It starts with isolating the first-stage downloader and confirming the victim’s IP and hostname, then moves into DNS and infrastructure discovery to show how the infected machine locates internal resources like the Domain Controller. The focus then shifts to C2 triage, highlighting persistent beaconing, unusual ports, and TLS handshake inspection to uncover how malware blends in with legitimate traffic. Finally, it covers persistence and exfiltration, demonstrating how HTTP POST requests and specific URI patterns reveal stolen data and how TrickBot categorizes it. Overall, the quiz emphasizes applying precise Wireshark filters, interpreting session metadata, and linking packet-level evidence to attacker techniques.

### Operation: SANDSTONES: A Deep-Dive Analysis of the TrickBot “rob13” Infection.**
**Phase One: Initial Compromise & Host ID**
1. When attempting to identify the first stage of an infection (the external downloader), which query would you use?
- `http.request`
- `http.uri == “rob13”`
- `http_request_method == GET`
- `ip.addr contains “malicious”`

A is Correct: This pulls all HTTP GET/POST requests, showing the initial call to the first-stage downloader.
B is Incorrect: This looks for the later C2 campaign tag, which isn't present in the very first packet.
C is Syntax Error: Wireshark filters use dots (.), and values like GET must be in quotes.
D is Syntax Error: `ip.addr` only accepts numerical values; it cannot contain a text string.


2. After filtering for the initial request, what is the Source IP of the infected victim machine?
- 10.2.17.2
- 192.168.1.1
- 10.2.17.101
- 172.16.0.50

A is Correct: This is the confirmed internal IP of the victim workstation in this pcap.
B is Incorrect: This is the IP of the Domain Controller, not the infected client.
C is Incorrect: This is a common home network default; it doesn't match this lab environment.
D is Incorrect: This is a generic private IP used as a distractor.


3. Looking at the first HTTP request, what is the malicious Domain (URL) the victim is communicating with?
- Destinostumundo[.]com
- checkip[.]amazonaws[.]com
- Sandstones[.]local
- microsoft-update[.]com

A is Correct: This is the actual domain hosting the first-stage downloader in this pcap.
B is Incorrect: This is a legitimate Amazon service used later for an IP check.
C is Incorrect: This is the internal AD domain name, not an external URL.
D is Incorrect: This is a common typosquatting distractor that doesn't appear here.


### Phase Two: Initial Compromise & Host ID Continued
4. In that same HTTP request, what is the specific URI (path) being requested from the server?
- `.rob13/90/gate.php`
- `/index.html`
- `/admin/login.php`
- `/layout/recruiter.php`

A is Correct: This is the verified path for the TrickBot downloader on that domain.
B is Incorrect: This is the URI structure for later C2 beacons, not the initial stage.
C is Incorrect: This is a generic default page and isn't the malicious file.
D is Incorrect: While suspicious-sounding, it isn't the artifact in this investigation.


5. To identify the NetBIOS name of the infected host (10.2.17.101), which query is the most efficient?
- `ip.src == 10.2.17.101 && nbns`
- `ip.addr == 10.2.17.101 && dhcp`
- `nbns.name_contains == 10.2.17.101`
- `find.host == “10.2.17.101”`

A is Correct: This isolates Name Service traffic specifically from our victim's source IP.
B is Incorrect: While DHCP can show a name, `dhcp` is often a failed alias; `bootp` is the standard filter.
C is Syntax Error: `nbns` doesn't support a `name_contains` operator for IP addresses.
D is Syntax Error: `find.host` is not a valid Wireshark display filter.


5. After running the NBNS query, what is the confirmed hostname of the infected machine? 
- DESKTOP-5BT9E19
- DESKTOP-ADIJBT3
- SANDSTONES-DC
- WIN-SERV-2019

A is Correct: This is the workstation name associated with IP 10.2.17.101 in this capture.
B is Incorrect: This would be the name of a Domain Controller, not a workstation.
C is Incorrect: This is a hostname from a different malware capture.
D is Incorrect: This is a generic server name used as a distractor.


Phase Three: DNS & Infrastructure Discovery
7. In order to find how the host located the Domain Controller (DC) via Advice Directory Service Records, which query should we run?
- `dns.flags.response == 1`
- `dns_type == SRV`
- `dns.qry.type == 33`
- `ip.proto == DNS & srv.record`

A is Correct: Type 33 is the numerical identifier for SRV records used by Windows to find DCs.
B is Incorrect: This shows every DNS response, creating too much noise.
C is Syntax Error: Wireshark uses dots and integers for types.
D is Syntax Error: `srv.record` is not a valid field in the Wireshark filter engine.


8. Looking at the SRV records, which internal IP address is identified as the Domain Controller for the SANDSTONES domain? 
- 10.2.17.1
- 10.2.17.101
- 10.2.17.255
- 10.2.17.2

A is Correct: This IP responds to the `_ldap` queries and handles Kerberos requests.
B is Incorrect: This is likely the default gateway (router), not the DC.
C is Incorrect: This is the IP of the infected victim machine.
D is Incorrect: This is the broadcast address for the subnet.


Phase Four: C2 Triage & Behavior
9. When triaging top-talkers in the conversations window, why is the IP 179.191.108.56 prioritized over the Domain Controller (10.2.17.2)?
- It shows persistent beaconing behavior to an external, non-business IP.
- It has a higher total byte count than the DC.
- It’s the only IP using the TCP protocol in the entire pcap.
- It’s located on the same subnet as the victim machine.

A is Correct: Persistent external beacons are a higher threat priority than internal DC traffic.
B is Incorrect: The DC actually has more bytes; volume doesn't always equal threat.
C is Incorrect: Most hosts in this pcap use TCP; this isn't a distinguishing factor.
D is Incorrect: This is an external IP, not on the local subnet.


10. To investigate the specific port used by this suspicious IP, which query would we use to isolate its traffic?
- `tcp.port == 443`
- `addr.ip == 179.191.108.58`
- `ip.addr == 179.191.108.58`
- `ip.address == 179.191.108.58`

A is Correct: This correctly filters for all traffic to and from the C2 IP.
B is Incorrect: This shows standard HTTPS, hiding the malicious Port 449 traffic.
C is Syntax Error: The correct field name is `ip.addr`, not `addr.ip`.
D is Syntax Error: `ip.address` is not a valid filter.


11. After isolating the IP, we see it communicating on port 449. Why is this significant in a malware investigation?
- It’s the default port for secure web browsing (HTTPS)
- It indicates the host is attempting to use an encrypted VPN. 
- It proves that the attacker has successfully gained Domain Admin privileges.
- It’s a known non-standard port frequently used for Trickbot C2 communication.

A is Correct: Port 449 is a specific fingerprint often seen in TrickBot infections.
B is Incorrect: Port 443 is the default for HTTPS; 449 is a red flag.
C is Incorrect: While encrypted, 449 isn't a standard VPN port.
D is Incorrect: Port choice alone doesn't prove privileges.


12. When we want to inspect the TLS handshake details for this suspicious C2 connection, which query would we use?
- `ip.addr == 179.191.108.58 && tls.handshake.type == 1`
- `ip.addr == 179.191.108.58 && tls.type == clien_hello`
- `tls_handshake_type == 1 && src.ip == 179.191.108.58`
- `ip.address == 179.191.108.58 && ssl.handshake`

A is Correct: Type 1 is the numerical code for a Client Hello, containing the SNI.
B is Incorrect: Wireshark uses numerical values for handshake types.
C is Syntax Error: Wireshark uses dots and `ip.src` rather than `src.ip`.
D is Syntax Error: `ip.address` is invalid; `ssl.handshake` is the deprecated name for `tls`.


13. Using the TLS query, we see a variety of different Server Names (SNI). What does this suggest? 
- The user is visiting 50 different websites at the exact same time. 
- The DC is trying to load balance the external connection.
- The malware is using SNI Spoofing to blend in with legitimate traffic. 
- The victim’s browser cache is being cleared automatically by the system. 

A is Correct: Rotating famous domains on one IP is a classic tactic to bypass firewall signatures.
B is Incorrect: The timestamps make this highly unlikely for a human.
C is Incorrect: DCs don't load balance external C2 traffic.
D is Incorrect: Browser cache clearing doesn't generate new TLS handshakes.


Phase Five: Persistence & Exfiltration
14. To check if the malware is attempting to steal stolen data (such as system info or cookies), which query would we use to find HTTP POST requests containing potential exfiltration?
- `http.post.exfil == true`
- `request.type == POST_DATA`
- `ip.proto == HTTP && method == POST`
- `http.request.method == “POST”`

A is Correct: This is the standard filter to see data sent out from the victim to a server.
B is Incorrect: exfil is not a valid Wireshark field.
C is Syntax Error: `request.type` is not a valid field.
D is Syntax Error: Wireshark uses `http.request.method`.


15. In this pcap, we see POST requests to URIs ending in /81, /83, or /90. What do these numerical suffixes indicate in a rob13 infection?
- Data Categorization: Each number identifies the type of stolen data (such as /81 for passwords).
- Success Codes: They show the upload was 81% complete.
- Encryption Keys: They represent the bit-length of the encryption used.
- Server IDs: They represent which of the 90 different C2 servers is receiving the data.

A is Correct: These are specific TrickBot commands; /81 is for credentials and /90 is for system info.
B is Incorrect: HTTP status codes are 3 digits and not found at the end of a URI.
C is Incorrect: Encryption keys are not transmitted openly in the URI.
D is Incorrect: These numbers designate content, not server ID.

