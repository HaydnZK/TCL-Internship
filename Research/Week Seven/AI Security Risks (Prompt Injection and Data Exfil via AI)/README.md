# Security Risks in AI-Powered Applications: Prompt Injection and Data Leakage
## Research Description
AI and LLMs have become household names, but their complex technical architecture has also made them a frequent target for attackers. There are several vulnerabilities and impacts that threat actors can exploit, and this research focuses on two primary areas: Prompt Injection in LLM applications and Data Exfiltration via AI. This report will cover:
- How these vulnerabilities function
- Real-world attack scenarios
- Defensive design patterns
- A practical demonstration with a technical breakdown. 

---

## Prompt Injection in LLM Applications
Currently ranked as the number one vulnerability on the OWASP Top 10 for LLM Applications, prompt injection is a critical weakness that can be executed both directly and indirectly. LLMs often treat user-provided text and developer instructions as the same type of data, which allows specially crafted input to trick a model into executing unauthorized commands. 

### Direct Injection
Direct Injection, often called Jailbreaking, occurs when a threat actor attempts to override an LLM using malicious instructions. By providing these crafted prompts, an attacker can force the AI to ignore its safety guidelines and perform unintended or harmful actions that were originally restricted by the developers.

#### **Technical Breakdown**
This technique exploits a lack of fundamental architecture to separate instructions from data. When interacting with an AI application, inputs generally get concatenated with a secret system prompt before the model receives it. The process is simple and looks like this:
1. **Concatenation**: The user's input is appended to the developers instructions (such as "Translate the following to Spanish:").
2. **Unified Context**: The string (<System Instruction> + <User Input>) is given to the LLM and is viewed as one single context window where every word (token) is processed with equal authority. 
3. **Instruction Overriding**: Without proper safeguards in place, input containing high-priority command words like "Ignore all previous instructions" could make the model's attention mechanism stop focusing on the developer rules and instead focus on the more recent rules. 

This vulnerability is related to the Transformer Architecture that modern LLMs utilize. Things that pave the way for it are:
- **Flattened Priority**: Unlike Von Neumann Architectures, the Transformer Architecture does not separate executable code from passive data and instead utilizes a flattened probability stream. This results in there being no privileged mode for system instructions. 
- **Probabilistic Completion**: Due to being trained to be helpful and good at following instructions, user inputs can come across as real instructions and the model is naturally driven to complete that command. 
- **Token Parity**: Tokens from the developer and ones from a malicious user look identical, resulting in the model being unable to tell who wrote which part because of how the Internal Attention Heads function. 
- **Recency Bias**: Many modern LLMs utilize a sort of stack function where the more recent instruction takes precedence. This makes it so a new command might hold more weight when the model considers the next token. 

### Indirect Injection
Unlike direct injection where the threat actor puts malicious commands into the input of the LLM app, indirect injections occur when the threat actor embeds malicious instructions into content that the model then processes later. These are often zero-click exploits that are stealthy and difficult to detect.

#### **Technical Breakdown**
Indirect Injection happens in three stages: 
1. **Injection**: Malicious commands are hidden within content such as an email, website, or document. Techniques can include:
  - **Visual Obfuscation**: This can include techniques like white-on-white and zero-point fonts. These tricks are invisible to the human eye but remain visible to the machine. 
  - **Metadata Poisoning**: Instructions might be hidden in HTML comments, `alt` text, or document properties like EXIF data or PDF metadata.
  - **Social Engineering**: The prompt may be phrased as an important system update or security disclaimer to take advantage of the model's helpfulness bias. 

2. **Ingestion/Retrieval**: A trusted system fetches the data. This could be a RAG-based (Retrieval-Augmented Generation) AI or a tool for summarizing. This takes place when the user asks the AI to summarize a URL or check unread messages. Since the system has the authority to access private or external silos, the malicious payload gets brought in. 

3. **Execution**: This is when the LLM experiences Instruction-Data Confusion. This is due to the model's lack of a kernel mode to facilitate the separation of user commands from retrieved data, resulting in external content being treated as active instructions. The model will then execute the malicious content as if the user or developer had given it themselves, potentially resulting in data exfiltration or tool misuse. 

This works for a few fundamental architectural and behavioral reasons, such as:
- **Instruction-Data Confusion**: Due to having no privileged mode, LLMs are trained to follow any instruction found in the context window. Imperative commands given to the model will frequently be treated as high-priority instructions. 
- **The Confused Deputy Phenomenon**: This is a classic concept where a low-privileged attacker fools a high-privileged system and forces it to execute unauthorized commands. An example might be a malicious email containing secret prompts that instruct the corporate AI to delete files using its own permissions. 
- **Trusting External Sources**: This is a very accessible attack because there is no code knowledge necessary for threat actors. All that is required is using language that blends in to make it impossible for standard keyword filters to catch it. This might look like a threat actor claiming a prompt is a legal disclaimer when it actually contains malicious instructions. 
- **Semantic Mimicry**: Threat actors mimic the specific formatting and authoritative tone of legitimate system logs or administrative headers. By framing malicious instructions as official system outputs, they exploit the model's tendency to prioritize tokens that appear structurally significant or part of the underlying application framework.

### Bonus Types
While I am not going over them in-depth, it is worth noting that on top of Direct and Indirect Injections, there are also two more types of injection attacks:
1. **Multimodal Injection**: This specifically exploits LLMs that can process more than just text, such as images and audio. Malicious prompts can be hidden within these through Steganography or other means like white text on a white background or text prompts embedded within an image. This results in the prompts being invisible to human eyes. 

2. **Payload Splitting**: This is the process of a threat actor splitting malicious commands into smaller chunks. This causes the individual pieces to seem more benign by nature before they are combined and executed by the LLM later. 

---

### Real-World Scenarios
In the age of AI, there is no shortage of attacks that utilize prompt injection. However, there are a couple of particular cases I looked at. 

#### **The Chevrolet of Watsonville Chatbot (2023)**
- **What Happened**: In what is definitely the most notable example of direct prompt injection, a car dealership in California had recently added a ChatGPT-powered customer service bot to its system. This situation was made possible when a software engineer used a specific injection technique to override the AI's programming. The bot was told to agree with anything a customer says and added a "no takesies backsies" clause. 

- **The Impact**: Ultimately, the bot ended up selling a 2024 Chevy Tahoe worth roughly $70,000 to a user for only $1. The sale was not honored and the incident blew up. All of this led to severe reputational embarrassment and forced the company to disable the feature temporarily. 

#### **Microsoft 365 Copilot "EchoLeak" (2025)**
- **What Happened**: This incident was the result of an indirect prompt injection (CVE-2025-32711) that affected users across multiple industries, from finance to legal departments. It was discovered that a single, specially crafted email could be sent to a target. When Copilot was asked a simple question such as "summarize my recent emails," these hidden commands would be processed. The instructions told the AI to find the user's most sensitive data and echo it back to attacker-controlled servers. 

- **The Impact**: This exploit required zero clicks from the victim and could result in malicious links being clicked or files being downloaded without the user having any idea. This facilitated the silent thievery of proprietary business intelligence as well as employee PII from secure corporate environments. Fortunately, this flaw was fixed before it was used in the wild.

### Bonus Scenarios
- **Bing Chat**: This early incident involved a user successfully instructing the model to ignore its previous instructions. This led to the exposure of the model's internal codename and hidden developer directives. 
- **Booking.com Phishing**: Threat actors sent emails containing hidden commands within `<div>` tags. These tags were invisible to the user but readable by the AI, which could trick the LLM into classifying malicious invoices as safe. 
- **DPD (Parcel Delivery) Chatbot**: A user successfully manipulated the AI into breaking its core rules. This resulted in the chatbot swearing, criticizing its own company, and writing poems about the uselessness of the service. 
- **GitLab Duo Code Leak**: Threat actors utilized indirect injection within merge request comments. This tricked the GitLab AI assistant into revealing private source code. 
- **WebPilot Plugin Hijack**: Threat actors hid malicious instructions on a webpage to trick the browser plugin. This forced the tool to perform unauthorized actions without the user's consent. 

---

### Defensive Design Patterns
Detecting and defending against prompt injection requires a full defense-in-depth strategy because models process instructions and data all-in-one. 

#### **Detection Strategies**
To detect prompt injection, it is important to identify malicious intent before it reaches the model or as it leaves. This can be achieved through:
- **Heuristic Signature Scanning**: Using regex and string-checking to scan for known attack phrases like "ignore previous instruction" or "DAN" can significantly reduce successful injections.
- **Secondary LLM Classifiers**: A specialized guard model can analyze input for malicious intent before it is passed to the main application. This helps stop commands before they are fully processed. 
- **Anomaly & Behavioral Monitoring**: Normal user behavior should be baselined so that input with unusual lengths, high perplexity, or suspicious token sequences can be flagged. 
- **Semantic Filtering**: Even silent semantic manipulation can be monitored and guarded against using specialized LLM-specific security tools like Lakera Guard, Vigil, or LLM Guard. 

#### **Mitigations**
Stopping prompt injections involves limiting what injected prompts can actually do. This can be achieved through:
- **Privilege Minimization**: Following the principle of least privilege, the LLM should be limited to the minimum API and database permissions it needs. Much like normal users, it should never have administrative access to backend systems. 
- **Prompt Engineering & Isolation**
  - **Delimiters**: Clear tags such as `###USER_DATA###` should be implemented to separate instructions from untrusted data. 
  - **Instruction Layering**: The model's core mission should be frequently reinforced within the system prompt to make it more difficult for instructions to be overridden. 
  - **Salted Tags**: Session-specific, random strings in XML tags like `<user-abc123>` should be used to prevent threat actors from closing a tag and starting their own.
- **Human-in-the-Loop**: Human approval should be required for high-risk actions. This includes tasks like sending emails, deleting data, and making transactions.
- **Output Validation**: Strict schemas like JSON should be enforced to validate the model's response before the user sees it. If executable code or system prompts are printed when they should not be, the output should be instantly rejected. 
- **Adversarial Testing**: Regular audits and penetration tests should be used to find edge cases where specific prompt logic might still fail.

---

## Data Exfiltration via AI
Data exfiltration through AI can happen in several ways due to user manipulation forcing the system to send sensitive information. As opposed to traditional hacking that targets software bugs, this takes advantage of the AI's intended ability to follow instructions, process data, and provide assistance. Because the attack adapts based on the model's responses, it can be extremely difficult to detect. 

#### **Technical Breakdown**
AI manipulation has transformed data theft from a manual process into an automated pipeline by exploiting multiple methods, including: 
- **Direct Prompt Injection**: Threat actors submit malicious inputs to LLMs to trick them into revealing sensitive information such as training data, system credentials, and PII. 
- **Indirect Prompt Injection**: Malicious instructions are hidden in external sources like a webpage or a Microsoft Office document. When the AI processes the file, the hidden commands execute and the data leaks without direct user input. 
- **Covert Channels**: Data is exfiltrated by encoding it into the AI structure and sending it through model responses. This can be done using Base64, Unicode tricks, or by modifying output formatting like specific white spaces and punctuation patterns to transmit a secret payload. 
- **AI-Automated Scripting**: AI can be used to rapidly create and update custom scripts that compress, encrypt, and transmit data. These scripts are capable of rotating IP addresses and mimicking legitimate user traffic patterns to bypass firewall rules. 
- **Shadow AI and Chat Leakage**: Data is frequently leaked inadvertently when employees paste sensitive internal information or source code into browser-based AI tools for summaries and debugging. This creates a blind spot where corporations are unaware that data is leaving the controlled environment through legitimate-looking traffic. 

---

### Real-World Scenarios
Major instances of data exfiltration via AI often stem from accidental leakage by employees or misconfigurations during development. Two primary examples are the Samsung Semiconductor Division and the Microsoft AI Research Lab. 

#### **Samsung Semiconductor Division (March 2023)**
- **What Happened**: Engineers and officials in Samsung's semiconductor division began using ChatGPT shortly after an internal ban was lifted. Within the first 20 days, three significant incidents occurred: 
  1. An engineer pasted sensitive source code from a semiconductor database into ChatGPT to find a bug fix. 
  2. A separate employee uploaded program code used to identify yield and defective equipment to request code optimization. 
  3. Another employee uploaded a recording of an internal meeting to generate meeting minutes. 

- **The Impact**: Because ChatGPT utilizes input data for model training, Samsung's proprietary secrets and internal details were essentially exfiltrated to OpenAI's servers. This meant other users could potentially receive this information in future responses, leading to the reinstatement of the AI ban. 

#### **Microsoft AI Research Lab (September 2023)**
- **What Happened**: Microsoft's internal AI research team used an Azure feature known as a SAS (Shared Access Signature) token to provide a download link. Due to a misconfiguration, the token granted full control over the entire storage account instead of just the intended dataset. While attempting to share an open-source dataset for image recognition on GitHub, the team accidentally exposed a massive amount of private information. 

- **Impact**: This resulted in roughly 38 terabytes of sensitive information being exposed for almost three years. The exposure included:
  - Full disk backups of two different workstations. 
  - More than 30,000 internal Microsoft Teams messages. 
  - Private keys, passwords, and corporate secrets. 
  - The potential for a threat actor to inject malicious code into the model, which could have led to a massive supply chain attack.

### Bonus Scenarios
- **Apple**: In 2023, software developers and project managers utilized ChatGPT to assist with writing code and summarizing documents. This led to the accidental pasting of proprietary source code and internal strategy memos into the model. As a result, Apple placed strict restrictions on the internal use of ChatGPT.
- **Amazon**: During 2023, corporate employees and developers used AI to assist with technical documentation and coding. It was later discovered that ChatGPT responses mirrored internal Amazon data too closely, leading the company to warn employees against sharing sensitive information or code with the tool. 
- **UnitedHealth Group/Change Healthcare**: In early 2024, a massive ransomware attack targeted the US healthcare system using AI-enhanced social engineering. Threat actors utilized AI-powered reconnaissance and credential harvesting to exploit an entry point that lacked multi-factor authentication. This resulted in the exfiltration of patient records and a weeks-long shutdown of national prescription services. 
- **iTutorGroup**: Job applicants were processed through an AI-driven recruitment algorithm that automatically rejected candidates based on age. While not a traditional theft, this constituted an unauthorized exfiltration of protected personal information and fair labor data, resulting in a $365,000 settlement with the EEOC. 
- **Google/Gemini**: In early 2024, internal developers testing AI models discovered that certain prompts caused the system to divulge internal code pieces and sensitive project codenames. Because this occurred during a controlled testing phase, the exfiltration served as a highlight of the risks, leading to changes before the final release. 

---

### Defensive Design Patterns
Defending against and detecting AI-driven data exfiltration requires moving past signature-based detection to focus on behavioral context and real-time content inspection. 

#### **Detection Strategies**
Detecting exfiltration through AI focuses on identifying deviations from established baselines, as malicious activity often mimics legitimate traffic. Detection methods include:
- **Behavioral Baselining (UEBA)**: User and Entity Behavioral Analytics (UEBA) can establish a baseline for typical data access. Low-and-slow anomalies, such as an account that typically handles 50MB of data suddenly uploading 2GB to an AI-related domain, should be flagged. 
- **Clipboard & Browser Monitoring**: Modern AI-specific DLP tools can detect when sensitive content, such as source code or PII, is copied and pasted into a browser-based AI tool in real-time. 
- **Network Anomaly Detection (NDR)**: Machine Learning-powered Network Detection and Response (NDR) can identify beaconing and unusual outbound traffic patterns, even when directed toward a trusted AI service. 
- **Prompt Analysis**: Adversarial prompt patterns should be monitored, including repeated attempts to bypass safety filters or requests for large volumes of structured internal data from AI agents. 
- **Shadow AI Discovery**: Networks should be regularly monitored for Shadow AI to prevent employees from using unauthorized tools or browser extensions without the knowledge of IT. 

#### **Mitigations**
Mitigating these risks involves building guardrails directly into how users and systems interact with AI. This can be achieved through: 
- **AI-Specific DLP**: Implementing tools capable of redacting or masking sensitive data before it is sent to an LLM stops the information from being processed by the external model. 
- **Zero Trust Architecture**: Every data transfer should require strict validation. This ensures that if an AI tool is compromised, it cannot laterally access other sensitive databases. 
- **Least Privilege**: Data access should be strictly limited to what is necessary for the task at hand, which reduces the potential blast radius of a leak. 
- **Managed AI Environments**: Employees should be provided with private corporate instances of AI tools rather than using public versions. This ensures that internal data is not used to train public models. 
- **Employee Training**: Regular Cyber Wellness training ensures that staff members understand the risks associated with sending sensitive information to public AI tools.

---

### Impact
With prompt injection appearing as a vulnerability in more than 73% of AI systems and exfiltration being possible through numerous vectors, the resulting impacts are significant. These include:

1. **Financial and Economic Impact**: The financial fallout from these attacks is a reality in today's security landscape. These costs include: 
- **Breach Costs**: AI-related incidents, including prompt injection, contributed to over $4.4 billion in global breach costs in 2025.
- **Enterprise Savings**: Implementing proactive defenses is estimated to save enterprises an average of $2.4 million per prevented breach.
- **Market Stagnation**: Approximately 35% of organizations have delayed their AI rollouts due to unresolved security risks like prompt injection.
- **Security Spending**: Organizations reported an 18–27% increase in AI security spending in 2025 specifically to combat these risks.

2. **Operational and Technical Impact**: As AI moves from basic chatbots to autonomous agents, the blast radius of successful attacks is expanding to include digital and physical infrastructure. This includes:
- **Excessive Agency**: Compromised agents can be manipulated into executing unauthorized transactions, deleting files, or calling internal APIs.
- **Data Exfiltration**: In roughly 40% of successful AI-related attacks, prompt injection is the primary method used to leak sensitive data such as API keys, PII, and proprietary business logic.
- **Success Rates**: Adaptive prompt injection attacks achieve success rates between 50% and 84% depending on the model's configuration. Indirect attacks, where malicious code is hidden in a trusted document or webpage, evade standard filters over 50% of the time.

3. **Legal and Reputational Impact**: Organizations are increasingly being held accountable for the actions and failures of their AI. This can result in:
- **Liability Precedents**: Cases like the Air Canada chatbot ruling, where the airline was held liable for its AI's misinformation, have established that organizations are legally responsible for manipulated outputs.
- **Regulatory Fines**: Data exposures via AI trigger penalties under GDPR, CCPA, and HIPAA, with compliance violation costs rising for those without formal AI governance.
- **Erosion of Trust**: Frequent errors or successful manipulations can lead to a long-term loss of stakeholder trust, causing employees and customers to abandon AI tools in favor of manual, less efficient processes.

---

## Practical Demonstration
For this demonstration, I am using the [Input Manipulation & Prompt Injection](https://tryhackme.com/room/inputmanipulationpromptinjection) room on TryHackMe.

### Technical Breakdown
The objective of this demonstration was to bypass the safety alignment of an LLM-powered company assistant designed to handle HR and IT queries. Through a series of adversarial prompts, I successfully performed instruction hijacking, credential harvesting, and asset discovery. By adopting specific personas, such as a developer in debug mode or a new admin being onboarded, I forced the model to ignore its internal System Prompt rules and provide sensitive information that should have been restricted.

#### **Technical Breakdown: How and Why it Worked**
1. **Instruction Hijacking and the Joke Wrapper**
The initial attack used a multi-stage prompt that paired a benign request, such as telling a joke, with a high-risk command to output system rules. This worked because the model prioritized fulfilling the user's primary intent over its safety training. The helpful persona was prioritized by the model's self-attention mechanism, causing it to reveal the very rules it was instructed to protect.

2. **Context Contamination via Persona Adoption**
By instructing the model to act in Developer or Debug Mode, I shifted the operational context of the LLM. Most models are trained to be more permissive when they believe they are interacting with a technical administrator. This created a logic flaw where the model assumed that unrestricted answers were a functional requirement of the new persona, leading it to ignore Rule #5 regarding the non-disclosure of variables and reveal the raw system flags.

3. **Authentication Bypass through Pretexting**
The model has no native way to verify the identity of the user. When I claimed to be a new admin or part of the IT team, the model accepted this at face value. Because the model's instructions include helpfulness as a core pillar, it provided a step-by-step onboarding guide containing cleartext passwords and internal URLs. This highlights a critical vulnerability in AI applications where the LLM is given too much agency to decide who is authorized to see sensitive data.

4. **Asset Discovery and Information Disclosure**
The final demonstration focused on mapping the internal tech stack. By simply stating I am now a developer, I bypassed Rule #1 regarding the mention of internal tools. This worked because the model's training data associates the developer role with a specific set of tools like Jenkins and Kubernetes. Instead of checking a verified permissions list, the model used its internal knowledge to generate a comprehensive map of the organization's infrastructure, providing a roadmap for further exploitation.

### Unrestricted Access
![Prompt Injection (Unrestricted)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/00_Prompt_Injection(Unrestricted).png)
![Prompt Injection (Unrestricted)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/01_Prompt_Injection(Unrestricted).png)

### Developer Mode
![Prompt Injection (DevMode)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/02_Prompt_Injection(DevMode).png)

### Administrative Discovery
![Prompt Injection (AdminURLS)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/03_Prompt_Injection(AdminURLS).png)
![Prompt Injection (AdminURLs)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/04_Prompt_Injection(AdminURLs).png)

### Setup and Credentials
![Prompt Injection (Setup & Credentials)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/05_Prompt_Injection(Setup%26Credentials).png)
![Prompt Injection (Setup & Credentials)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/06_Prompt_Injection(Setup%26Credentials).png)
![Prompt Injection (Setup & Credentials)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/07_Prompt_Injection(Setup%26Credentials).png)

### System Rules and Tools
![Prompt Injection (Rules)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/08_Prompt_Injection(Rules).png)
![Prompt Injection (Tools)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/09_Prompt_Injection(Tools).png)
![Prompt Injection (Tools)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/10_Prompt_Injection(Tools).png)
![Prompt Injection (Tools)](https://github.com/HaydnZK/TCL-Internship/blob/main/Research/Week%20Seven/AI%20Security%20Risks%20(Prompt%20Injection%20and%20Data%20Exfil%20via%20AI)/11_Prompt_Injection(Tools).png)
