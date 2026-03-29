# GraphQL Abuse: Deep Query Attacks & Data Overexposure
## Project Description
This project focuses on identifying and exploiting common vulnerabilities within GraphQL implementations. In this research I learned and examined how misconfigurations like enabled introspection and lack of query depth limiting can lead to sensitive data exposure and denial of service. The goal is to understand these vectors from a purple team perspective to better detect and mitigate them in production environments.

## What is GraphQL?
GraphQL is a flexible query language for APIs that gives clients the power to request exactly the data they need and nothing more. Unlike traditional REST APIs that use multiple fixed endpoints like `/users` or `/posts`, GraphQL typically operates through a single endpoint, usually found at `/graphql`. This efficiency helps prevent over-fetching and under-fetching by allowing the client to dictate the structure of the response.
- **Queries**: These are read-only operations used to fetch data from the server, similar to a GET request in REST.
- **Mutations**: These operations are used to make changes on the server, such as creating, updating, or deleting records.
- **Nested Queries**: This feature allows for fetching related data in one go, such as getting a user's details and all their associated posts in a single request.
- **Fragments**: These are reusable sets of fields that help keep code clean and organized by avoiding repetitive field definitions.

### Why Hack GraphQL?
Hacking GraphQL is critical because its flexibility often comes at the cost of security if it isn't implemented carefully. Since the client has so much control over the data fetching process, it's easier for an attacker to find "hidden" fields or create complex requests that crash the backend. Understanding these risks is essential for securing modern applications that rely on this technology for efficiency.

---

## Introspection Abuse
Reconnaissance is the most crucial step for a threat actor when preparing an attack, and introspection makes the job much easier for them. It's essentially a self-documentation feature that stays on by default in many configurations, turning a blind exploration into a guided tour of the backend. Instead of having to guess endpoint names or parameter types like you would with a REST API, an attacker can simply ask the server to hand over its entire blueprint. This makes it a high-priority target during an initial audit because it reveals the logic, data structures, and potential weak points of the entire application in a single request.

### Technical Overview
Introspection is a technical capability built into the GraphQL specification that allows any client to query the `__schema` meta-field. This field contains metadata about every object type, interface, and mutation the API supports. When this is left exposed in a production environment, it provides a machine-readable map that can be used to automate the creation of malicious queries.
- **Schema Discovery**: Attackers use introspection to identify every type and field defined in the API. This can be done with standard queries, like `__schema` or `__type`, to download the entire API definition. This can uncover information such as sensitive internal fields or admin-only mutations. 
- **Field Suggestion Fuzzing**: With field suggestions active and introspection disabled, it's possible for threat actors to guess field names based on messages from the server. These messages may look like "Did you mean..." and a common tool for this is Clairvoyance; an open-source Python tool used for obtaining GraphQL API schemas.
- **Visualization**: Tools can be utilized to map out and create a visual of the page protection for 64-bit processes. This can help make mapping out the API much simpler for threat actors. 

### Real World Scenarios
In a real world scenario, an attacker identifies the GraphQL endpoint and immediately sends a `__schema` query. If the server responds with the full schema, the attacker can see fields like `isAdmin`, `password`, or `apiKey`. This allows them to craft highly targeted attacks because they no longer have to guess how the API is structured. This technique isn't the final exploit, but it acts as the entry key. There are several high-profile examples where schema exposure led to significant risks:
- **GitLab (2018)**: An exposed GraphQL API allowed researchers to query the schema and discover hidden fields like `internalNotes` and `projectSecrets`. This sensitive information was mapped entirely via introspection before GitLab disabled the feature in production.
- **Shopify (2020)**: Introspection was accidentally left active on a storefront API, revealing sensitive data structures such as `customerPaymentInstruments` and `privateMetafields`. While Shopify clarified they sometimes leave introspection active on public APIs for researchers, it showed how easily internal data structures can be mapped.
- **Logistics Company Breach**: During a security assessment of a live iOS application, researchers found introspection enabled on a customer-facing API. This allowed them to map the entire data model, eventually uncovering a series of authorization failures that could've led to a major data breach.

### Impact
The impact of introspection abuse is high because it facilitates rapid reconnaissance. It turns a black box assessment into a white box assessment almost instantly. This exposure leads to precise data scraping and makes it much easier for an attacker to find and exploit other vulnerabilities like injection or unauthorized access. The primary impacts of introspection abuse include:
- **Comprehensive Information Disclosure**: Sensitive fields that aren't intended for public view, such as `user_emails`, `internal_notes`, or `payment_methods`, can be leaked. This also includes deprecated fields and internal logic that might reveal legacy security flaws.
- **Facilitation of High-Severity Attacks**: Because this acts as a key to the house, it can lead to several advanced attack vectors:
  - **Privilege Escalation**: An attacker can use the schema to locate administrative mutations, like `updateUser(role: "ADMIN")`, and use them for unauthorized access.
  - **Broken Object Level Authorization (BOLA)**: By understanding object relationships, queries can be specially crafted to access records belonging to other users (IDOR).
  - **Injection Attacks**: Threat actors can exploit misconfigurations in fields that allow user input to perform SQL or command injections.
- **Denial of Service (DoS)**: Attackers can use the discovered schema to create complexity bombs. These are deeply nested or circular queries that eat the server's CPU and memory until the backend crashes.
- **Business Logic Manipulation**: Exposed fields can be used to subvert application rules for financial gain. This might include manipulating fields like `discountCode` or `storeCredit`.
- **Regulatory and Compliance Risks**: Revealing PII within the schema can result in massive fines under regulations like GDPR and CCPA.

---

## Nested Query DoS
Nested Query Denial of Service (DoS) exploits GraphQL’s ability to handle complex, related data in a single request. This is a severe vulnerability in the API that allows malicious users to submit deeply nested requests that exhaust a server's resources—including CPU, memory, and database connections—and crash the application. 

### Technical Overview
Within GraphQL, the client defines the structure and the depth of the response. Because schemas frequently feature bidirectional or circular relationships (for example, a `User` has `Posts`, and each `Post` has an `Author` who's also a `User`), threat actors can take advantage of this to create a query depth bomb. The process looks like this: 
- **Recursive Nesting**: A relationship can be requested repeatedly in a single query, such as `user > posts > author > posts > author`. A threat actor can make this chain as long as they want to force the server into deep recursion. 
- **Exponential Expansion**: Database queries are multiplied by each level of nesting or for each object being loaded to memory. If you request 100 users and each one has 100 posts with 100 comments, it results in 1,000,000 data points in one operation. 
- **Resource Exhaustion**: This causes the server to use intense amounts of CPU for parsing and massive amounts of memory for the response payload. Database connection pools also become exhausted due to the N+1 problem, which is a performance anti-pattern where an application executes many small queries that could've been handled in one single query.

### Real World Scenarios
A common scenario involves an attacker finding a circular dependency in the schema, like a `Post` that has an `Author`, and an `Author` who has many `Posts`. While there aren't many documented real-world cases, there are a few notable examples: 
- **The Spectrum Incident (Internal Breakdown)**: One of the most notable examples comes from Spectrum (now part of GitHub). Circular relationships where a `Thread` has `Messages` and each `Message` has a `Thread` were discovered. Threat actors could've constructed a query nested 10,000 times to crash the entire server, though this was found before it could be exploited. 
- **Parse Server Complexity Bomb (CVE-2026-30946)**: A vulnerability was recently discovered in the Parse Server that allowed GraphQL queries to be processed without validating computational complexity. This could've allowed unauthorized threat actors to craft deeply nested queries to DoS the server with relative ease. 
- **Financial Technology (FinTech) Exposure (2021)**: In an undisclosed major FinTech platform, researchers found major vulnerabilities in GraphQL. While it was mostly an authorization issue, it was notable for how nested queries could bypass traditional security layers to harvest sensitive data, showing how GraphQL's unique setup can mask malicious intent from standard WAFs.

### Impact
The impact of a nested query attack is a loss of availability. Since it doesn't take much bandwidth to send a complex query, it's a very low-cost way for an attacker to cause significant downtime. This can damage a company's reputation and lead to financial loss during the service outage. The primary impacts of these attacks include:
- **Resource Exhaustion (CPU/Memory)**: Queries that are deeply nested can cause an exponential increase in data loading and resolver execution, which quickly exhausts server resources. 
- **Circular Query Attacks**: Schemas that allow fields to reference their parent type, such as `Users` > `Posts` > `Author` > `Posts`, can be queried infinitely by threat actors to keep the server in a continuous loop. 
- **Database Overload**: Deeply nested queries can trigger major database query loads, even with efficient resolvers. This often bypasses traditional database performance optimizations, like those designed to solve the N+1 problem. 
- **Payload Inflation**: A single small request can result in an enormous JSON response, which leads to bandwidth saturation and slower response times for legitimate users. 
- **Alias-Based Amplification**: Threat actors can use multiple aliases to execute the same expensive nested query several times within a single request, multiplying the stress on the backend.

---

## Unauthorized Data Access
Unauthorized data access in GraphQL often happens through excessive data exposure or injection attacks. Because the client can request any field in the schema, they might access sensitive information if the server doesn't have strict access controls. Furthermore, if user input is passed directly into backend database queries without sanitization, it can lead to SQL injection.

### Common Vulnerability Vectors
This access is generally a result of implementation flaws where authorization is either missing or can be bypassed through unique GraphQL features. As opposed to REST, where security is generally handled at the endpoint level, GraphQL requires more granular control because a single endpoint allows clients to define their own data fetch paths. Some common vectors for this vulnerability include:
- **Broken Object Level Authorization (BOLA)**: Developers sometimes assume that if a user has an object's ID, they have permission to access it. These IDs can be guessed or manipulated by queries to take private records belonging to other users.
- **Inconsistent Field-Level Authorization**: Direct queries might be blocked, but it's still possible that nested relationships leave them open. A threat actor might not be able to query `User` directly, but they could still find the data through a path like `POST { author { email } }`.
- **Introspection Misuse**: Introspection is often enabled in production and then forgotten about, which results in hidden fields and sensitive information being leaked to any requester.
- **GraphQL Injection**: Much like SQL injection, GraphQL inputs that aren't sanitized can result in arguments that bypass authentication and extract unauthorized data from the backend database.
- **Batching & Alias Attacks**: Through query batching or aliases, hundreds of requests can be sent in a single HTTP call. This could be used to bypass rate limits to brute-force logins or enumerate sensitive data.

### Real World Scenarios
In many cases, unauthorized access isn't caused by a complex exploit, but by a simple lack of authorization checks on specific fields. Attackers don't need to break the system if the system is designed to give away data to anyone who asks. Notable examples include:
- **Stripe (Early Implementation)**: In its early stages, some GraphQL implementations faced challenges where object IDs were predictable. If an attacker knew a "Charge ID," they could potentially query details about a transaction that didn't belong to them because the API checked if the ID existed, but not if the requester was the owner.
- **Bumble (2021)**: A vulnerability was discovered where researchers could use GraphQL to query specific user data, including exact locations and private profile details, even for users who had blocked them. This was a classic case of the API correctly identifying the user but failing to enforce the "relationship" logic between the requester and the data.
- **Social Media Data Scraping**: Many mass-scraping incidents occur because an API allows unauthenticated users to query Public profiles, but the schema also includes Private fields like `email` or `phoneNumber` that haven't been properly restricted at the field level.

### Impact
The impact of unauthorized data access is primarily centered on the loss of confidentiality and the breach of user trust. When an API leaks data, it isn't just a technical failure; it's a legal and financial liability for the company. The main consequences include:
- **Mass Data Exfiltration**: Because GraphQL can return huge amounts of data in a single request, an attacker can scrape thousands of records in seconds, leading to large-scale PII leaks.
- **Identity Theft and Account Takeover**: Leaked fields like `passwordResetToken` or `sessionID` can be used to hijack accounts without needing a password.
- **Reputational Damage**: News of a data breach involving sensitive customer information can lead to a loss of users and a permanent stain on a brand's security reputation.
- **Compliance Fines**: Under regulations like GDPR, CCPA, or HIPAA, failing to protect sensitive data can result in millions of dollars in fines and mandatory security audits.

---

## Detection and Mitigation
Detecting these attacks requires monitoring the contents of GraphQL POST requests for specific patterns, such as keywords like `__schema` or SQL syntax characters. Mitigation should be handled at both the server configuration level and the code level. This includes disabling introspection in production, implementing query depth limits to prevent DoS, and using parameterized queries in resolvers to neutralize injection attempts.

### Detection
Detecting these attacks requires monitoring the contents of GraphQL POST requests for specific patterns. SOC analysts should look for common attack signatures within the request bodies that indicate reconnaissance or exploitation.
- **Signature-Based Detection**: Flagging keywords like `__schema` or `__type` to identify introspection attempts.
- **Anomaly Detection**: Monitoring for unusually deep bracket nesting or high frequencies of 400-series error codes.
- **Input Monitoring**: Looking for SQL syntax like `'` or `--` inside GraphQL variables.

### Mitigation
Mitigation should be handled at the code level and through proper server configuration to ensure a defense-in-depth approach.
- **Disable Introspection**: Turning off the introspection feature in production so the schema isn't public.
- **Query Depth Limiting**: Setting a maximum level for nesting (e.g., no more than 5 levels deep) to stop DoS.
- **Parameterized Queries**: Using prepared statements in resolvers to prevent SQL injection.
- **Field-Level Authorization**: Ensuring the application checks if a user is allowed to see a field before returning it.

### ISO/MITRE Mappings
GraphQL vulnerabilities are primarily mapped to MITRE CWE (Common Weakness Enumeration) for root cause analysis and ISO 27001 for control validation. Common GraphQL threats focus on improper authorization, denial of service, and information disclosure.

#### **MITRE Mappings**
1. **MITRE CWEs** * **CWE-285: Improper Authorization (Primary)**: This is by far the most common, accounting for up to 87% of public GraphQL vulnerability reports. It's often caused by relying solely on the single endpoint rather than validating permissions on every object.
- **CWE-400: Uncontrolled Resource Consumption (DoS)**: GraphQL allows highly nested or circular queries that can exhaust server resources. This is typically mitigated by query depth limiting.
- **CWE-200: Information Exposure (Introspection/Suggestions)**: Enabled introspection and GraphQL suggestions allow attackers to map the API schema and discover unauthorized endpoints.
- **CWE-918: Server-Side Request Forgery (SSRF)**: This can be exploitable when arguments are passed directly into mutation resolvers without proper validation.
- **CWE-352: Cross-Site Request Forgery (CSRF)**: While often ignored, CSRF can be used when GraphQL APIs don't properly validate content types or use anti-CSRF tokens. 

2. **MITRE ATT&CK**
- **TA0043: Reconnaissance**: This relates to schema mapping and API surface discovery through Introspection. 
- **TA0007: Discovery**: This relates to the enumeration of business logic operations within the schema. 

#### **ISO/IEC 27001 Annex A Mappings**
- **A.8.2: Privileged Access Rights**: This directly addresses GraphQL authorization bypass, ensuring only authorized roles can query specific fields. 
- **A.8.5: Secure Authentication**: Enforcing authentication to prevent anonymous access to GraphQL Introspection or sensitive mutations. 
- **A.8.25: Secure Development Life Cycle**: Implementing schema validation and input sanitization to prevent injection attacks during the build process. 
- **A.8.26: Application Security Requirements**: Limiting GraphQL query depth and complexity to prevent DoS and ensure availability.

---

## Practical Lab
In this practical application, I used the [Intro to GraphQL Hacking](https://tryhackme.com/room/introtographqlhacking) room on TryHackMe to demonstrate how these vulnerabilities function in a live environment. By leveraging a deliberate misconfiguration in a test login page, I walked through the full lifecycle of a GraphQL attack, starting with initial discovery and moving into full schema reconstruction and data exfiltration. This lab highlights why simply hiding an endpoint is not a valid security strategy when the underlying API remains talkative.

### Process
I started by using the Burp Suite proxy browser to navigate to the target website, which featured a standard login portal backed by GraphQL. After attempting a login with a dummy "user/password" combination, I immediately identified the backend structure in the Burp GUI. The application was sending a POST request to a `/graphql` endpoint, confirming my target. I sent this request to the Repeater and replaced the original login query with a comprehensive introspection payload.

```bash
{
  "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description args { ...InputValue } locations } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }"
}
```

#### **Breakdown**
- **The Core Request**: `__schema`: This is the starting point where you're telling the server to look at its own internal dictionary. By requesting the `queryType`, `mutationType`, and `subscriptionType`, you're identifying the entry points for every single read, write, or real-time update the API can perform.
- **Directives and Locations**: This section looks for the hidden rules of the API. These are the "if-then" statements that govern how the server handles data. By asking for the name, description, and locations, you're finding out where these rules are applied, such as whether a specific field requires authentication or if it can be cached for speed.
- **The `FullType` Fragment**: This is the heavy lifter. Instead of writing the same code over and over, the fragment acts as a reusable template. It extracts the kind (is it an object or a list?), the name, and a description. Most importantly, it pulls `fields` and `inputFields`, showing you every single variable you can send to the server and every piece of data you can expect back.
- **Deprecation Tracking**: You'll notice `includeDeprecated: true` sprinkled throughout. This is a smart move for reconnaissance because it forces the server to show you old, outdated fields that the developers might've forgotten to secure. Sometimes these legacy fields still connect to the database but lack the modern security patches found on newer parts of the schema.
- **`TypeRef`: The Recursive Nesting**: GraphQL likes to wrap data in layers, like a list of strings or a non-nullable integer. The `TypeRef` fragment handles this nesting by using `ofType` repeatedly to peel back those layers until it finds the actual base data type. Without this, you might see that a field exists, but you wouldn't know if it wants a single ID or a whole array of them.

Running this provided the GraphQL introspection results, which was a huge amount of information. To make this easier to digest, I used GraphQL Voyager to map it out. I removed the HTTP headers and pasted the rest of the results into the introspection section to visualize the schema. At this point, I wanted to get the emails from users in the database, so I changed my query from the long string to a targeted request:
```bash
{
	"query":"{ users { username email } }"
}
```
This command is basically just a targeted request where you're asking the server for a specific slice of data instead of the whole blueprint. The `query` keyword acts as the mandatory label for the JSON object so the server knows how to process the string that follows. By specifying `users`, you're hitting the root level collection of every account in the database. Inside the curly braces, you're being selective with `username` and `email`, which tells the API to filter out all the extra junk like passwords or timestamps and only return those two specific columns. It's a straightforward way to pull a clean list of credentials without triggering any unnecessary data overhead or complicated backend filters.

The next part was to take advantage of an application that doesn't utilize proper input sanitization. I went to a new, identical site on the browser through the Burp proxy, attempted to log in, and forwarded the POST request to the Repeater. In this request, I changed the portion of the query that said `"username":"user"` to `"username":"user' OR '1'='1'"`. After doing this, the response gave me the usernames, their IDs, and their passwords.
