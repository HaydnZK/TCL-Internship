# MITRE ATLAS: Adversarial AI Techniques
## Research Description
This project focuses on the study of adversarial AI through the lens of the MITRE ATLAS framework. I selected two specific techniques to analyze, exploring their technical definitions, the strategic motivations of attackers, and the practical workflows used to compromise machine learning systems. By examining real-world attack scenarios, I assessed the potential security impacts on model integrity and data privacy. The final component of my research identifies critical defensive measures, including both detection strategies and prevention techniques, to better secure AI-driven applications against sophisticated adversarial threats.

---

## 1. AML.T0018: Manipulate AI Models
This technique focuses on an adversary making unauthorized changes to the model's parameters, architecture, or behavior after it has been created.

### Technique Overview
#### **Definition**
AML.T0018 is a technique within the MITRE ATLAS framework where threat actors alter a machine learning model to achieve various goals. These objectives include altering model behavior, introducing new vulnerabilities, or implanting malicious code. This is achieved by modifying the model's weights, architecture, or embedded files, which can result in unintended, malicious, or incorrect outputs.

#### **Why attackers use it**
Unlike traditional Data Poisoning, which occurs during the training phase, this attack happens post-training. It is frequently used to create backdoors. There are three primary sub-techniques used by attackers to compromise model integrity or behavior:
- **Backdoor ML Model/Poison AI Model (AML.T0018.000):** Threat actors manipulate model weights to alter performance and behavior. This can be done through:
  - Directly changing the model's weights
  - Training the model on poisoned data
  - Interfering with the fine-tuning or training process
- **Modify AI Model Architecture (AML.T0018.001):** Threat actors redefine the model's internal structure. This can include:
  - Adding or removing layers
  - Altering pre-processing or post-processing operations
- **Embed Malware (AML.T0018.002):** Threat actors hide malicious code inside the model's file format. Generally, this code is intended to automatically execute once the model is loaded into memory.

### Attack Workflow
This technique generally follows a four-step pattern that allows a threat actor to progress from initial reconnaissance to final impact.

#### **How the technique works**
1. **Reconnaissance and Access:** The threat actor gains initial access to the target model. This is usually accomplished through an ML Supply Chain Compromise, such as breaching a model registry like Hugging Face or a private GitHub repository.
2. **Analysis:** The actor reverse-engineers the model architecture or parameters. This is done to identify trigger areas where small changes can have significant impacts on the output.
3. **Manipulation:** Once triggers are identified, the actor performs the actual modification. These methods include: 
  - **Weight Modification:** Modifying numerical values (weights and biases) to insert a backdoor.
  - **Architecture Change:** Adding or removing layers, or injecting a separate network into the computation graph to hijack specific inputs.
  - **Malware Injection:** Embedding malicious code into the model file (for example, in serialized formats such as `pickle`) which executes when the model is loaded.
4. **Verification and Deployment:** Before the tampered model is used, the actor verifies the effectiveness of the changes. This is often done through an offline proxy version to ensure it passes standard accuracy tests for benign data while failing on the trigger data.

#### **Where it appears in real-world systems**
This technique is especially dangerous within systems that frequently update or download from third-party services. Notable examples include:
- **Financial Fraud and AML Systems:** Actors manipulate Anti-Money Laundering (AML) models to ignore specific transaction patterns associated with their attacks, creating a blind spot in automated monitoring.
- **Open-Source Model Registries:** Actors upload poisoned versions of popular models that include malware or backdoors, affecting any developer who integrates them into their applications.
- **Autonomous and Physical Systems:** Actors manipulate models to misclassify specific objects, such as treating a stop sign as a speed limit sign, only when subtle physical triggers are present. This can be used against self-driving cars or facial recognition systems.
- **AI Agent Workflows:** Actors poison the metadata of systems using Model Context Protocol (MCP) or similar tools, causing the AI agent to follow malicious instructions when utilizing the compromised tool.

### Real-World Examples
#### **Hugging Face Model Poisoning (2024)**
In early 2024, security researchers discovered more than 100 malicious AI models uploaded to Hugging Face. These models were modified to include hidden malware that would execute Remote Code Execution (RCE) attacks on a user's machine once the model was loaded into a common environment like PyTorch or TensorFlow. This is a clear example of AML.T0018.002 (Embed Malware).

#### **Shanghai Tax Authority Case (2018-2021)**
In this case, threat actors defrauded the government of $77 million over several years by bypassing ML-enabled liveness detection. They used specialized mobile phones to inject deepfake videos created from stolen photos into the facial recognition system, simulating blinking and nodding. This allowed them to fraudulently register shell companies and issue tax invoices.

#### **Bypassing Cylance's AI Malware Detector (Case Study)**
In a benchmark case study in the MITRE ATLAS database, researchers analyzed the Cylance AI-based malware detection engine and successfully manipulated its decision-making logic. They tricked the AI into misclassifying malicious code as safe by appending specific strings from benign files to known malware.

#### **"Sleepy Pickle" Exploits (2024)**
Researchers demonstrated the Sleepy Pickle technique, which targets how AI models are serialized. By manipulating the model file, they injected a payload that remains dormant until the model is used in a specific way, acting as a logic bomb. It can then quietly change model weights in memory to alter outputs or steal sensitive information.

#### **Backdoored Facial Recognition Systems**
Researchers demonstrated how modifications to internal weights could result in facial recognition software working as expected for most users while granting access to anyone wearing a specific trigger accessory, such as uniquely patterned glasses.

#### **Microsoft Edge AI Evasion (Simulated)**
Documented in MITRE ATLAS, researchers manipulated the underlying ML components of Microsoft Edge's AI-driven security features to evade detection. This demonstrated that even secured, consumer-facing products are vulnerable if an actor understands and modifies the internal thresholds or layers of the model.

### Security Impact
This is a severe issue because it targets the core logic of the AI system, facilitating silence, persistence, and targeted damage. Unlike input-based attacks, this manipulation can permanently alter the system logic or use the model file to facilitate traditional cyberattacks.

- **Loss of Integrity:** The model can no longer be trusted. It may silently misclassify critical data, such as allowing fraudulent transactions or failing to detect security threats.
- **System Compromise via Embedded Malware:** Attackers use model formats like `pickle` to hide malicious code. When the model is loaded, this code executes and grants Remote Code Execution (RCE).
- **Persistence:** Modifying the model itself ensures malicious behavior remains active even if the system is restarted or input data is cleaned.
- **Bypassing Security Controls:** Manipulated models can be engineered to specifically ignore an attacker's activity while appearing to function normally for everyone else.

#### **What damage it can cause**
The consequences of these impacts can be massive:
- **Massive Financial Loss:** Successful manipulation of financial models can result in the loss of millions of dollars.
- **Theft of Intellectual Property:** Actors can force a model to leak sensitive training data or exfiltrate proprietary weights, leading to significant R&D losses.
- **Operational Disruption:** In manufacturing or industrial settings, tampered model weights can lead to equipment failure or sabotage of production lines.
- **Threats to Public Safety:** In safety-critical systems like autonomous vehicles or healthcare, model manipulation can lead to vehicles ignoring traffic signs or medical AI misdiagnosing conditions.
- **Reputational Ruin:** Deploying a poisoned or backdoored model leads to long-term damage to customer trust and brand credibility.

### Defensive Measures
Defending against AML.T0018 requires preventing unauthorized access to model artifacts and ensuring integrity throughout the AI lifecycle.

#### **Detection strategies**
- **Cryptographic Signing:** Digitally sign model files at the time of creation. If the signature does not match when the model is loaded, the system should automatically reject it.
- **Hardened Model Repositories:** Store models in centralized, read-only registries with strictly controlled access.
- **Zero-Trust Access (IAM):** Use Identity and Access Management to ensure only a small group of authorized engineers can modify model weights. Every access attempt should require Multi-Factor Authentication (MFA).
- **Network Isolation:** Keep model training and storage environments on private subnets that are not reachable from the public internet.
- **Malware Scanning:** Run specialized scanners on incoming model files to detect embedded malicious code before they enter the environment.

#### **Prevention techniques**
- **Model Provenance and Lineage:** Maintain a detailed history for every version of a model to allow for quick rollbacks to a known-safe version.
- **Confidential Computing:** Run models in Trusted Execution Environments (TEEs) to encrypt the model while it is in use in RAM, preventing live-patching of weights.
- **Adversarial Red Teaming:** Regularly employ security experts to attempt to backdoor models to find weaknesses in the supply chain or developer workflows.
- **Golden Image Verification:** Periodically compare the production model's hash against a golden image stored in an air-gapped environment to detect silent drift or tampering.
- **Drift and Anomaly Monitoring:** Set up automated alerts for output drift. If a model behaves differently on specific data types, it could indicate a hidden backdoor has been activated.

---

## 2. AML.T0011: User Execution: Unsafe ML Artifacts
This technique focuses on scenarios where threat actors rely on a user performing a specific action to trigger the execution of malicious code within an AI system. 

### Technique Overview
#### **Definition**
While AML.T0018 focuses on the threat actor changing model weights and architecture, AML.T0011 involves tricking a user into running a poisoned or unsafe artifact. This attack exploits the way AI and ML frameworks load and process files. Many popular model formats, such as Python's `.pickle` or `.pth`, are executable by nature. This means they can run arbitrary code as soon as they are opened. 

#### **Why attackers use it**
This technique is favored by threat actors because it exploits the trust developers place in pre-trained models. Rather than attempting to breach a hardened firewall, an attacker can wait for a researcher to run `torch.load()` on a malicious model from a public repository. Attackers utilize this because:
- **Unsafe ML Artifacts (AML.T0011.001):** The adversary creates or distributes malicious files, such as models in `.pickle` or `.pth` formats, that contain embedded code. When a user loads these files into an ML framework, the malicious code automatically executes on the victim's system.
- **Path of Least Resistance:** Uploading a poisoned model to a public repository is often much easier than attempting to breach a corporate network directly. 
- **Full System Access:** While other attacks might only manipulate AI output, this technique can grant Remote Code Execution (RCE). The actor gains control of the underlying server or workstation rather than just the model's logic. 
- **Bypasses Static Scanning:** Most traditional antivirus tools do not know how to look inside complex ML tensors and serialized pickle files for malicious code. 
- **Persistence:** Once integrated by a developer, the unsafe artifact enters the corporate pipeline. This allows malware to spread to internal servers and remain active for long periods. 

### Attack Workflow
This technique utilizes a mix of social engineering and technical exploitation to compromise a system. 

#### **How the technique works**
1. **Weaponization:** The threat actor creates a model file, generally in `.pickle`, `.pth`, or `.joblib` formats, and injects a malicious payload into the deserialization logic. The payload is designed to run automatically once the file is opened. 
2. **Luring:** The actor uploads the trojanized model to a public hub like Hugging Face or GitHub with an eye-catching name or claims of high performance to trick users into downloading it. 
3. **User Execution:** A researcher or developer downloads the model to test it. They run standard commands, such as `model = joblib.load('cool_new_model.pkl')`. 
4. **Payload Trigger:** As the library begins to unpack the model, the hidden malicious code executes instantly in the background. This usually occurs without the user noticing any changes in the model's actual performance. 
5. **Compromise:** The code may open a reverse shell, steal environment variables like AWS or OpenAI API keys, or install a backdoor on the machine. 

#### **Where it appears in real-world systems**
This technique targets any system where a human interacts with external model files, essentially turning the AI model into a trojan horse.
- **Developer and Data Science Workstations:** This is the primary target. A developer may download a popular model to test it. Because developers often have high-level permissions and unencrypted API keys stored in `.env` files or AWS credentials, loading a single unsafe file can grant full access to cloud infrastructure. 
- **MLOps and CI/CD Pipelines:** This is the factory that builds and deploys AI. Automated pipelines may pull a base model from a public registry to retrain or fine-tune it. If the pipeline does not use weight-only loading, the malicious artifact can execute on the build server, poisoning the entire software supply chain. 
- **AI Inference Servers:** These are live production servers. An actor might infect a third-party model used for specialized tasks like medical image analysis or fraud detection. If the production server loads the unsafe artifact during a reboot or update, the actor can gain a reverse shell in the heart of the production network. 
- **Edge Devices and IoT:** These devices often pull model updates automatically. Because these devices frequently lie outside traditional firewalls, an unsafe artifact can turn a fleet of smart devices into a botnet or allow an actor to shut down physical machinery. 

### Real-World Examples
#### **Public Model Hubs (Hugging Face)** Researchers have identified over 100 malicious models on the Hugging Face platform that enabled Remote Code Execution (RCE). In one notable case, a user uploaded a PyTorch model that, when loaded, established a reverse shell to an attacker-controlled host.

#### **"NullifAI" Evasion (2025)** A novel technique dubbed NullifAI was discovered where attackers used malformed Pickle files to bypass automated security scanners. These models successfully executed malicious Python code, typically a reverse shell, upon being loaded by standard PyTorch or TensorFlow environments.

#### **Post-Exploitation Droppers** Security firms have found malicious ML models in the wild acting as malware droppers. These files, often distributed via forums or GitHub, embedded scripts that injected Cobalt Strike beacons or Metasploit payloads directly into system memory, turning a model-loading process into a full-scale network intrusion.

#### **Fake AI SDKs and Packages** In mid-2025, malicious packages appeared on the Python Package Index (PyPI) mimicking official AI libraries to trick developers. Some packages were downloaded over 1,600 times in less than 24 hours, demonstrating how quickly unsafe artifacts can infiltrate professional workflows.

#### **Pickle-Based "Sleepy Pickle" Attacks** Real-world demonstrations have shown that actors can weaponize `.pth` and `.pkl` files to steal data and silently modify models in place. This allows an attacker to maintain a foothold where the model appears to function correctly while executing malicious background tasks.

### Security Impact
This is often more dangerous than a typical AI attack because it shifts from manipulating data to full compromise of the host system.
- **Arbitrary Code Execution (ACE/RCE):** This is the primary impact. Loading a malicious file allows an attacker to run any command on the victim's machine with the same permissions as the user who opened it.
- **Credential and Secret Theft:** Once the unsafe code runs, it can scan the environment for API keys, `.env` files, and SSH keys, which are then exfiltrated to an attacker-controlled server.
- **Lateral Movement:** If a developer loads an unsafe model on a workstation connected to a corporate network, the attacker can use that foothold to scan internal servers, databases, and repositories.
- **Supply Chain Infection:** If a malicious artifact is pulled into a CI/CD pipeline, the attacker can infect every model or update the company produces, turning the victim into an unwitting distributor of malware.

#### **What damage it can cause**
The consequences of this technique being exploited are severe:
- **Full System Takeover:** Attackers can install a reverse shell or a command and control beacon, giving them permanent remote access to the system.
- **Data Exfiltration:** Sensitive training data, proprietary architectures, or customer PII stored on the server can be stolen silently.
- **Ransomware Deployment:** Because the attacker has code execution, they can encrypt local files or the model database and demand a ransom for decryption.
- **Reputational and Legal Ruin:** Companies that accidentally distribute poisoned models to customers face massive liability, loss of trust, and potential regulatory fines.

### Defensive Measures
To defend against AML.T0011, it is vital to move away from executable model formats. Defense must occur before the `load()` command is run, treating AI models as untrusted code rather than static data. 

#### **Detection strategies**
- **Switch to Safe Formats:** Avoid Pickle-based formats like `.pkl`, `.pth`, and `.joblib`. Use `.safetensors` or ONNX instead. These formats are data-only and cannot execute Python code.
- **Weights-Only Loading:** If you must use PyTorch, always use the `weights_only=True` flag in your load function. This restricts the unpickler to basic data types and blocks the execution of complex malicious objects.
- **Sandboxing and Containerization:** Never load a third-party model directly on a main workstation. Run it inside a Docker container or virtual machine with no access to the network or sensitive environment variables. 
- **Model Signing and Verification:** Use tools to verify that a model has not been tampered with. Only pull models from verified organizations on public hubs.

#### **Prevention techniques**
- **Static Artifact Scanning:** Use tools like Picklescan to scan model files for dangerous opcodes before they are integrated into your code.
- **Egress Filtering:** Monitor the network for unusual outbound connections. If a model-loading process attempts to connect to an unknown IP address, it may be a reverse shell attempting to phone home.
- **Behavioral Monitoring:** Use runtime security tools to watch for suspicious system calls. An AI model should be performing math on the GPU, not attempting to read SSH folders or modify system files. 
- **Provenance Auditing:** Regularly audit your ML Bill of Materials (ML-BOM). If a model in your pipeline cannot be traced to a verified author, flag it for manual review.
