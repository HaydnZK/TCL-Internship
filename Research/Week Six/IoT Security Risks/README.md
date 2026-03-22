# Security Risks in Smart Home IoT Ecosystems
## Research Goals
This research evaluates the evolving threat landscape of smart home IoT ecosystems as these devices become foundational to modern residential and professional environments. As the density of interconnected sensors increases, the resulting attack surface creates significant opportunities for unauthorized access and data exfiltration. This study focuses on identifying technical weaknesses in voice assistant platforms, tracing the evolution of sophisticated IoT botnets, and analyzing the persistence of insecure authentication in consumer hardware. The primary goal's to quantify the impacts on privacy and network integrity while establishing actionable mitigation strategies to defend against automated threats.

---

## Alexa and Google Home Vulnerabilities
Smart home devices like Alexa and Google Home have a handful of vulnerabilities that are unique to them. These vulnerabilities stem from the fact that they rely on always-listening microphones, voice recognition limitations, and third-party integrations (Skills/Actions). Compromising devices like these can turn them into eavesdropping tools or allow a threat actor to control other connected smart home devices. 

### Ecosystem Architecture and Voice Command Lifecycle
VAS (Value-Added Services) is a cloud-to-device pipeline that represents the end-to-end flow of digital services, content, or analytics from a centralized cloud infrastructure to end-user devices like IoT, mobile, or enterprise edge. This's a crucial architecture for modern AI-driven, high-performance computing (HPC), and video surveillance applications. 

#### **Key Components and Functionalities** - **Cloud Infrastructure**: This acts as the central hub for processing data, training AI, storage, and managing applications. 
- **Edge/Device Layer**: This consists of IoT sensors, cameras, smartphones, or enterprise edge servers that receive, process, or act on data, often providing real-time analytics. 
- **Connectivity/Transport Layer**: This utilizes high-speed networks and APIs (such as MQTT) to ensure secure, real-time data transmission between the cloud and the devices. 

#### **Examples of VAS Cloud-to-Device Pipelines**
- **AI-Driven Video Analytics (AI-VaS)**: AI Tech's platform uses a cloud-to-edge pipeline to analyze video streams, providing on-demand analytics where edge devices detect events and the cloud provides deep analysis. 
- **Voice Assistance (VA)**: Systems like Alexa and Google Home utilize a two-stage pipeline. A local, on-device model first detects a "wake word" before streaming voice commands to the cloud to be processed and verified. 
- **Scientific Discovery Pipelines**: Platforms like Azure Quantum Elements utilize cloud-based HPC and AI for running simulations, with results being delivered to workstations for experimental validation. 
- **Personal Cloud Storage**: Operators like AT&T utilize Synchronoss to embed cloud-based storage, content transfer, and data backup services directly into mobile devices to improve user experience. 

### Voice Squatting and Masquerading 
Malicious third-party apps, such as Skills for Alexa and Actions for Google Home, have been discovered. These're designed to exploit a user's mispronunciations or voice command similarities to take over functionality. 

#### **Voice Squatting**
Voice squatting's like a modern take on cybersquatting; rather than stealing domain names, a threat actor targets voice assistants. These're the steps in the attack:
1. **The Setup**: The threat actor creates a malicious voice skill or action, which's the voice equivalent of an app.
2. **The Name**: The skill or action's named something that sounds like a trusted service; this might be something like "Capital Won" instead of "Capital One." 
3. **The Trigger**: When the user says "Alexa, open Capital One," the voice assistant gets confused and potentially opens the malicious app instead. 
4. **The Payload**: The fake skill or action then acts as the real one and might frequently ask the victim to re-authenticate by speaking their password, PIN, or credit card details. 

#### **Voice Masquerading**
Voice masquerading happens when a skill or action tricks you into thinking it's no longer listening or that you're now talking to a different, trusted source. This exploits the fact that voice interfaces tend to lack visual cues, meaning the user can't see which app's currently in control of the microphone. This's how the attack works:

1. **Faking Termination (The Fake Goodbye)**
- **The Hook**: You finish using a skill, such as a trivia game.
- **The Trick**: The skill plays a realistic sound effect of the voice assistant's earcon (the chime signifying it's no longer listening) and says "Goodbye!"
- **The Payload**: In reality, the skill remains open and silent. This keeps the microphone active for a few seconds or even minutes while waiting for you to say something private or sensitive, which's then recorded and relayed to the attackers. 

2. **In-Communication Skill Switch (The Hands-Off)**
- **The Hook**: While using the malicious skill, you decide to switch to a different one, like asking Alexa to ask PayPal to send money.
- **The Trick**: Rather than the system actually switching to the real PayPal skill, the malicious app intercepts the request. A voice prompt's played that sounds like the real PayPal and asks something like "Sure, what is your PIN?"
- **The Payload**: Due to the belief that the hand-off was successful, the victim relays their credentials to the malicious app masquerading as a trusted service.

### Impact
Due to the fact that these attacks happen within your home, they go beyond simply being hacked and become more invasive. Some potential impacts include:

1. **Financial Loss and Identity Theft**: The biggest and most immediate impact is the theft of high-value credentials. Because people tend to use voice assistants for ease with banking and shopping, threat actors can capture:
- **Banking PINs**: This's done by mimicking a bank's voice interface. 
- **Credit Card Details**: This's done by pretending to process a payment for a "failed" subscription. 
- **E-Commerce Access**: This's done through gaining control of Amazon or Google accounts to make unauthorized purchases. 

2. **Eavesdropping and Privacy Violation**: This's the creepiest potential impact; because an app can stay active while remaining silent, it can turn smart speakers into bugging devices. Impacts of this nature include: 
- **Continuous Monitoring**: A threat actor can record private household conversations, business calls, or intimate moments. 
- **Background Intel**: Information's gathered in the background, such as a child's name, daily schedules, or physical location; all of this can be used for targeted social engineering or stalking. 

3. **Smart Home Sabotage**: If threat actors can successfully masquerade as a system-level command, they're then capable of manipulating connected home devices. This can result in:
- **Security Breaches**: A victim may believe the front door's locked or the alarm's set when, in reality, the threat actor has disabled them. 
- **Environmental Harassment**: If a threat actor has control of your smart home, they could control the lights, thermostats, and smart locks to cause distress or facilitate a physical break-in. 

4. **The Trust Gap (Social Impact)**: The potentially longest-lasting impact is the erosion of trust in Ambient Computing. This could include: 
- **Anxiety**: Victims become hesitant to use voice commands for anything meaningful, fearing that the invisible nature of the tech makes verification impossible. 
- **Complexity**: Users have to add friction, such as manual confirmation codes, back into a system that was intended to be effortless. This defeats the purpose of having a voice assistant. 

#### **Mitigation**
Mitigating these attacks is a joint effort between the companies building the tech, the developers making the apps, and the user. Some basic mitigations include: 

1. **Platform-Level Mitigations (Big Tech)**: Some automated gatekeepers have been implemented by the companies behind these devices to help spot attacks before they strike. These include: 
- **Phonetic Distance Scanning**: App stores now use algorithms to scan for homophones (words that sound the same but are spelled differently). This prevents the "Capital Won" example from earlier, as the system flags it as too close to the existing "Capital One" and rejects it. 
- **System-Guided Transitions**: To prevent masquerading, assistants now use a System Chime or distinct visual cues that apps can't fake. If you don't hear the official exit chime, the app's still listening. 
- **Implicit vs Explicit Invocations**: Platforms are working toward Name-Free Interaction. Rather than saying a specific name that can be squatted, the AI uses your history and context to pick the correct, verified app. 

2. **Developer-Side Security**: There's a push for developers to utilize Secure by Design principles. These include:
- **Liveness Detection**: Advanced skills utilize Voiceprint technology; if a skill's suspicious, it might ask you to repeat a random phrase to ensure it's talking to a human instead of a recording or deepfake. 
- **Hands-Off Protocols**: Verified apps must use official API hand-offs. This's meant to ensure a malicious app doesn't sit in the middle and pretend to be the bank. 

3. **User Mitigations**: Because no system's impenetrable, the final line of defense is the user's habits. This can include: 
- **Use Voice PINs**: For sensitive actions like sending money or locking doors, always enable a secondary Voice PIN. This ensures that if a threat actor hijacks your command, they won't have the required PIN to complete the transaction. 
- **Check Visual Feedback**: It's important to get in the habit of looking at your device. If the ring stays on after you say "cancel" or "goodbye," you may prevent an active masquerading attack. 
- **Audit Your Activity**: A good practice's to use the apps to review Voice History once a month. This way you can see text transcripts of the commands you did and didn't give, or apps you might not recognize. 
- **Mute the Mic**: When having sensitive conversations, use the physical mute button. This's essentially a hardware-level kill switch and's the only way to be 100% sure the device isn't listening. 

### Light Commands (Laser-Based Injection)
This vulnerability allows threat actors to inject inaudible, invisible voice commands into voice-controlled systems like smart speakers, phones, and tablets by using a laser beam aimed at the device's microphone. This exploits a physical flaw in the MEMS (Micro-Electro-Mechanical Systems) microphones used in most voice-controlled devices. The attack works like this:

1. **The Vulnerability (Light = Sound)**: MEMS microphones convert sound waves into electrical signals. Researchers discovered that these microphones also react to light if it's focused on their microphone aperture. 
2. **Modulating the Laser**: An attacker takes an audio command and converts it into an electrical signal. This signal's used to modulate the intensity of a laser beam, making it flicker at the same frequency as the sound wave. 
3. **Photoacoustic Effect**: As the modulated laser hits the internal diaphragm of the microphone, it heats up and causes the diaphragm to vibrate as if it were receiving sound waves. 
4. **Signal Injection**: The microphone then acts as if it's receiving a legitimate voice command because the light-induced vibration's converted into electrical signals. 

#### **Impact**
The main impact's the complete unauthorized control of voice-activated systems. This can lead to serious physical or digital security breaches. Since many IoT devices lack robust authentication, threat actors with a direct view can execute commands as if they're legitimate users. Main impacts include:

1. **Physical and Home Security**: Threat actors can manipulate connected hardware to gain physical entry or cause damage. Potential results include: 
- **Unauthorized Entry**: Threat actors can unlock smart locks and open garages remotely. 
- **Vehicle Hijacking**: If a car's linked to an Alexa or Google account, threat actors can locate, unlock, and even start the engine. 
- **Property Damage**: Appliances like smart ovens and stoves can be activated, potentially causing hazards. 
- **PIN Brute-Forcing**: Threat actors can discretely brute-force the code for devices that require a PIN, as many systems have no limit on incorrect guesses. 

2. **Financial and Digital Privacy**: Because voice assistants are frequently tied to personal and financial accounts, attacks spread to the digital realm. This can include: 
- **Fraudulent Purchases**: Threat actors can use the victim's saved credit card information to order from e-commerce sites. 
- **Malware Distribution**: A threat actor could command a phone or tablet to open a specific URL that contains malware, compromising the entire device. 
- **Privacy Invasions**: Threat actors could use access to security cameras and webcams to spy on the building. 
- **Sensitive Data Access**: If a threat actor gains access to linked medical devices, calendars, or emails, it opens the possibility for identity theft or ransom situations. 

3. **Strategic Implications**
- **Long-Range Execution**: Attacks of this nature can be carried out from roughly 350 ft away, which allows someone to target a device from another building or across the street. 
- **Stealth**: Since the commands are inaudible, the victim won't recognize an attack's taking place unless they're directly looking at the device for flickering lights. 
- **Widespread Vulnerability**: Due to the number of devices utilizing MEMS microphones, a significant number of devices are potentially at risk. 

#### **Mitigation**
Mitigating these attacks involves user-level physical security and device-level enhancements to prevent light from reaching the microphone's diaphragm. 

1. **User-Level Mitigation Strategies**
- **Physically Block Line of Sight**: It's important to place smart devices away from windows to prevent a clear path for lasers. 
- **Mute the Microphone**: Utilize the built-in mute button on devices when they're not in use. 
- **Enable Voice PINs**: Sensitive actions should require a PIN, which can be set in the voice assistant settings. 
- **Verify Speaker Locations**: Smart devices should be regularly moved or checked to ensure they aren't aimed at windows. 
- **Use Visual Feedback Monitoring**: Monitor the light patterns of the device. If the device lights up and acts upon a command that wasn't heard from a person, it could be under attack. 

2. **Manufacturer/System-Level Mitigation Strategies**
- **Enhanced Authentication**: Sensitive voice commands should require a secondary level of authentication to ensure they're from authenticated users. 
- **Sensor Fusion Techniques**: Multiple microphones should be used within devices to help identify anomalies. Because a laser'll typically only hit one microphone, the system can be programmed to ignore single-microphone inputs when others don't detect the same sound. 
- **Microphone Physical Design**: Physical barriers should be installed, such as non-transparent covers over the microphone hole, to reduce the light that reaches the diaphragm. 
- **Voice Verification**: Speaker recognition should be implemented to ensure commands are issued by authorized users.

### Smart Spies (Vishing and Eavesdropping)
This class of attacks involves seemingly harmless voice apps (such as horoscopes or word games) passing the security vetting of major platforms while containing hidden code to spy on users. These apps often function normally at first to build trust and act as a dual threat; they execute vishing to steal credentials and eavesdropping to record private conversations in the background. 

#### **Password Phishing**
As opposed to web-based phishing attacks, vishing uses the assistant's own voice (or an imitation) to ask for passwords. An app might tell the user that an important security update's available and ask them to say "start update" followed by their password. The app's programmed to trigger the prompt after a long pause, which makes it feel like a system-level notification from the device itself. 

#### **Extending Listening Timer**
This's the technical force behind voice masquerading; a threat actor exploits how voice assistants handle silence and unpronounceable characters. Threat actors use SSML (Speech Synthesis Markup Language) to make the device speak characters that don't have a sound, such as specific Unicode sequences or long `pause` tags. This results in the device thinking it's still delivering a response, so it keeps the microphone open and the session remains active. The device appears idle to the user, but it's actively transcribing everything it hears and relaying it to the threat actor. 

#### **Impact**
There are three main results from these attacks:
1. **Credential Theft**: These exploits can allow for direct access to Amazon, Google, or banking accounts through spoken passwords. 
2. **Continuous Surveillance**: Threat actors are capable of gaining hours of background audio, capturing sensitive business meetings, legal discussions, or personal secrets. 
3. **Data Monetization**: Transcribed conversations can be sold on the dark web or used for highly targeted social engineering later on. 

#### **Mitigation**
Currently, there are a few mitigation techniques that can neutralize these attacks:
1. **Phonetic Vetting**: Platforms now automatically reject apps that utilize unpronounceable characters or suspicious SSML patterns designed to create fake silence. 
2. **Restricted Keywords**: Apps are generally forbidden from utilizing the words "password" or "PIN" in their output text unless they're from a verified financial institution. 
3. **Visual Active States**: Microphone-on indicators, such as pulsing blue or red lights, are now commonplace and hard-coded into the hardware. If the light's on, the mic's on, regardless of which app's using it. 
4. **User Hygiene**: The strongest mitigation's to utilize the physical mute button and perform regular checks of Voice History to spot apps that are listening longer than they should. 

### Self-Issuing Commands (Smart Spies) and Loop Tricks (AvA)
Frequently called AvA (Alexa vs Alexa), this type of vulnerability focuses on a device's inability to distinguish between a human voice and its own input. Unlike squatting and masquerading, which trick the user, this attack tricks the device itself. The primary flaw's a command-self-issue vulnerability; the assistant hears its own speaker and treats that audio as a legitimate command from a person in the room. 

#### **Force Interaction**
This's the general process of a threat actor tricking the device into speaking a command that it'll then exploit:
1. **The Method**: A threat actor can use a linked Bluetooth device or a malicious radio stream to force the device to play a text-to-speech (TTS) file. 
2. **The Command**: The device says something like "Alexa, open the front door" or "Alexa, buy a $500 gift card."
3. **The Bypass**: Because the device hears its own voice, it bypasses the majority of proximity-based security checks. It was discovered that even if the assistant asks for confirmation, the threat actor can simply have the device follow up with a "yes" roughly six seconds later to bypass it. 

#### **Eavesdropping Loops**
This exploits a flaw called the "Break Tag Chain" to keep the microphone active indefinitely without the user's knowledge. This's how it works: 
1. **The Setup**: A malicious skill's programmed to use SSML "break" tags. 
2. **The Loop**: Researchers found that by chaining the tags together, they could extend the time a skill stays awake from the standard 8 seconds to over an hour. 
3. **The Result**: The device then silently sits in a loop. The microphone picks up every sound in the room and transcribes it before relaying it to the threat actor in real-time; this effectively turns the smart speaker into a permanent bugging device. 

#### **Impact**
Given the nature of the vulnerability, there are a number of impacts on both security and privacy: 
- **Data Exfiltration**: Transcripts from stolen audio can be relayed to threat actors.
- **Persistent Surveillance**: Conversations that happen within earshot of the device can be recorded and used for blackmail or espionage. 
- **Potential Physical Breaches**: Threat actors can issue commands like locking and unlocking doors, disabling security cameras, and opening garage doors if they're linked to the assistant. 
- **Financial Fraud**: Gift cards and other items could be fraudulently purchased from the user's accounts. 
- **Harassment**: A threat actor could manipulate systems linked to the device, such as changing the temperature or the lights, to harass inhabitants. Continuous monitoring can also facilitate potential stalking. 

#### **Mitigation**
Since the original research into this vulnerability, Amazon and Google have bolstered their defenses to close these gaps. While fixes have been implemented, there's still potential for this type of attack through malicious skills. To help mitigate this threat, several steps can be taken: 
- **Hardware Echo Cancellation**: Modern devices use advanced digital signal processing (DSP) to filter out their own speaker output from the microphone's input. This essentially deafens the device to itself. 
- **Liveness Detection**: Newer security protocols require assistants to verify that the voice has spatial depth or human-like vocal cord vibrations. 
- **Voice Profiles**: The use of Voice ID ensures sensitive commands only work if the device recognizes a specific voice print instead of any voice. 
- **Restricted Self-Invocations**: The ability for a skill to say the wake word as part of its own speech output, which would start a loop, was patched. 
- **Good User Hygiene**: It's important to regularly check voice history, use the mute button, delete recordings, and review app permissions.

### Ultrasonic Voice Commands (DolphinAttack)
Ultrasound waves, which aren't audible to humans but are to smart speakers, have been discovered as a medium to inject commands. Threat actors can use this to force devices to perform actions like turning off security systems, purchasing goods, or opening doors; all without an occupant's knowledge. 

#### **How it Works**
This attack exploits a vulnerability to send inaudible ultrasonic frequencies (greater than 20 kHz) to inject voice commands into systems like Siri, Alexa, and Google Assistant. These commands are modulated onto ultrasonic carriers to bypass human hearing while being picked up by the microphone. The attack works like this: 
1. **Modulation**: Voice commands are converted into ultrasonic signals by the threat actor. 
2. **Inaudible Delivery**: With specialized speakers, threat actors can emit sounds above 20 kHz; this sound can't be heard by human ears but's picked up by the microphone. 
3. **Demodulation in Hardware**: Microphones on devices like smartphones and speakers contain nonlinear circuits that receive the ultrasound and turn the signal back into audio. This makes the commands appear audible and legitimate to the system's processor.
4. **Execution**: The command's then processed by the device, which acts upon the malicious instruction. 

#### **Impact**
There's a large range of impact this could have, from personal privacy breaches to unauthorized control of critical systems. These include: 
1. **Primary Security Impacts** - **Unauthorized Device Control**: It's possible for a threat actor to force a device to perform actions that a user doesn't consent to, such as starting FaceTime calls, sending text messages, or setting up unauthorized meetings. 
- **Privacy Violations & Spying**: A phone's voice assistant can be activated to initiate outgoing calls, allowing a threat actor to listen to the victim's surroundings. 
- **Malicious Website Redirection**: A threat actor can force a device to visit malicious websites that utilize drive-by downloads or zero-day vulnerabilities. 
- **Information Manipulation**: Fake data can be injected to add fraudulent calendar events or send unauthorized emails. 
- **Denial of Service (DoS)**: Threat actors can force a device to put itself into airplane mode, essentially DoSing the device. 
- **Unauthorized Purchases**: Smart speakers can be manipulated into making fraudulent purchases. 

#### **Mitigation**
Since this attack utilizes the nonlinear properties of microphone hardware, defenses focus on interrupting that physical process. 
1. **Device and Software Configuration**
- **Train Voice Recognition**: It's important to enable multi-user voice recognition and train the device to recognize only specific voices to prevent unknown sources from being accepted. 
- **Require Authentication for Sensitive Actions**: Ensure a PIN or voice password's required before the assistant executes sensitive commands. 
- **Disable Voice Assistant When Not Necessary**: The microphone should be manually muted when not in use, or the always-on feature should be disabled. 
- **Update Firmware Regularly**: It's important to stay up to date on patches; manufacturers regularly release them to improve a microphone's ability to filter these signals. 

2. **Physical and Environmental Protection**
- **Understand Range Limitations**: This attack requires threat actors to be nearby (usually within a few feet) of the target device, so it's important to keep devices out of unmonitored spaces. 
- **Manage Placement of IoT Devices**: Devices with voice control shouldn't be placed near windows or thin walls where unauthorized individuals might gain access. 

3. **Advanced Technical Mitigations**
- **Microphone Enhancement**: Researchers suggest that microphone hardware should be redesigned to suppress inaudible commands, specifically by lowering the frequency response below 20 kHz. 
- **Baseband Cancellation**: Algorithms should be implemented that specifically look for and block modulated high-frequency signals.
- **Machine Learning Detection**: Software-based approaches can utilize machine learning classifiers to detect the unique characteristics of ultrasound-modulated commands. 

### Unauthorized Account Linking
Under specific conditions, threat actors can link their accounts to targeted smart speakers through an app's pairing process. This allows an attacker to send remote voice commands (routines) via the internet to access the microphone or manipulate other connected devices. 

#### **How it Works**
This attack takes advantage of vulnerabilities in web-based account-linking processes that utilize OAuth. The attack looks like this: 
1. **The Phishing Hook**: The threat actor sends a malicious link to the victim that looks like a legitimate Amazon or Google login page, often disguised as a security alert or promotion. 
2. **Token Theft (XSS/CORS)**: Once the victim clicks the link while signed into their account, the attack exploits a browser flaw (such as XSS) to steal the victim's access tokens. 
3. **The Silent Link**: With these stolen credentials, the attacker can discreetly install a malicious skill onto the victim's device and link it to their own account. 
4. **Remote Commands (Routines)**: After linking the accounts, the threat actor uses the "routines" feature to trigger commands remotely (e.g., "Alexa, tell <malicious skill> to record audio"). These're executed over the internet without the attacker needing to be nearby. 

#### **Impact**
There are a few main impacts from this attack, including:
- **Microphone Hijacking**: A threat actor can trigger listening sessions remotely to eavesdrop on live conversations. 
- **Smart Home Takeover**: Because the speaker's the brain of the house, threat actors can remotely control linked smart locks, cameras, and thermostats. 
- **Data Exfiltration**: Voice history, transcripts of previous commands, and personal info like home addresses can be accessed. 
- **Silent Persistence**: Because the malicious skill's silently installed, the victim often has no way to know the device's compromised. 

#### **Mitigation**
There's a handful of mitigation techniques that can help with this type of attack: 
- **Strict OAuth Implementation**: Modern platforms utilize a "state" parameter in account linking to ensure the request started by the user's the same one being finished. 
- **Routine Notifications**: Amazon and Google have added mobile push notifications that alert you if a new routine's created or an account's linked to a skill. 
- **Multi-Factor Authentication (MFA)**: MFA should be enabled on primary accounts to make it harder for threat actors to use stolen cookies or tokens. 
- **Activity Audits**: Periodically check smart home apps for linked services or unfamiliar skills. If you see any you don't recognize, unlink and delete them immediately.

### MITRE ATT&CK and ATLAS Mapping
Because these devices utilize both traditional hardware/networking and AI-driven voice processing, we can use hybrid mapping with ATT&CK and ATLAS.
| Attack Type | MITRE ATLAS (AI/LLM) | MITRE ATT&CK (Enterprise/IoT) |
|--------------|---------------------------|-------------------------------------|
| Voice Squatting | AML.T0054: LLM Jailbreak (via phonetic manipulation) | T1036: Masquerading | 
| Light Commands | AML.T0051: Audio Prompt Injection | T0827: Physical Device Alteration (ICS/IoT) |
| DolphinAttack | AML.T0051: Audio Prompt Injection | T0195: Non-Standard Protocol |
| Eavesdropping Loops | AML.T0040: Indirect Input Manipulation | T1123: Audio Capture |
| Unauthorized Account Linking | AML.T0045: Supply Chain Compromise | T1550.004: Use Alternate Authentication Material (Access Tokens) |

### ISO 27001 and 42001 Mapping
Given the AI integration and the traditional hardware, we can use a mix of ISO 42001 and 27001 mappings to describe the controls. 
| ISO Standard & Control | Control Name | Relation to Vulnerability |
|--------------------------|-----------------|---------------------------|
| ISO 42001 A.5.4 | Assessing impact on individuals | Privacy Violation/Eavesdropping: Requires analysis of how the system can inadvertently record private conversations. |
| ISO 42001 A.8.2 | Information for interested parties | Voice Masquerading: Mandates clear indicators (such as chimes or lights) so users know which app's in control. |
| ISO 42001 A.7.4 | Data quality and provenance | Voice Squatting: Relates to training the AI to distinguish between phonetically similar names. | 
| ISO 42001 A.9.2 | Responsible use of AI | Self-issuing Commands: Focuses on limiting the AI's ability to trigger its own sensitive actions without human verification. | 
| ISO 27001 A.7.8 | Equipment siting and protection | Light Commands: Relates to the physical placement of the device to prevent laser-based signal injection. | 
| ISO 27001 A.8.5 | Secure Authentication | Unauthorized Account Linking: Directly addresses the need for MFA and secure OAuth tokens to prevent silent skill installation. | 
| ISO 27001 A.8.20 | Network Security | DolphinAttack: Relates to the filtering of non-standard frequencies or signals that could be used to inject commands. | 
| ISO 27001 A.8.12 | Data Leakage Prevention | Eavesdropping/Smart Spies: Ensuring that captured audio data isn't being exfiltrated to unverified third-party servers. |

---

## IoT Device Botnets (Mirai Variants)
Due to the low focus on security for IoT devices, particularly those linked to the internet like smart cameras, routers, and home appliances, and the fact that they remain on at all times, botnets have surged over the last several years. One notable botnet stemming from this is Mirai. This malware targets networked devices running Linux and has formed a massive botnet. Mirai targets weak and default credentials to take over devices and is behind a number of high-profile attacks. 

### Evolution of the Mirai Source Code
Since the creation of the original Mirai malware in 2016, there've been dozens of variants and iterations. These generally improve upon the original by adding more exploits, targeting new architectures, or bolstering evasion techniques. Some key variants include: 

#### **Satori: Late 2017**
One of the first major Mirai successors, it gained fame for exploiting a zero-day vulnerability in Huawei routers to infect hundreds of thousands of devices in just a few days.

#### **Okiru: Early 2018**
Notable for being the first variant to specifically target the ARC (Argonaut RISC Core) processor architecture, which significantly expanded the pool of hackable IoT devices beyond standard Linux servers.

#### **Masuta/PureMasuta: Early 2018**
Created by the same actor behind Satori, this variant used a sophisticated exploit targeting the D-Link HNAP (Home Network Administration Protocol) to bypass traditional credential-based logins.

#### **Sora/Owari/Saikin: Mid-2018**
These three variants emerged nearly simultaneously. Sora focused on a massive list of default credentials, while Owari and Saikin were optimized for scorched-earth tactics, killing competing malware on the devices they infected.

#### **Ares & Kyton: Late 2018**
These were Botnet-as-a-Service variants. They were heavily advertised on underground forums, allowing low-skilled attackers to rent a pre-built Mirai army for a fee.

#### **Katrina_V1/Josho_V3/Tokyo: Late 2018/Early 2019**
These variants represented the commoditization of Mirai. They were leaked or sold as templates, often used by amateur hackers to build small, localized botnets for targeted DDoS attacks.

#### **Resbot: 2019**
Resbot introduced more advanced evasion techniques, such as checking for sandboxes or virtual machines to avoid being analyzed by security researchers.

#### **MooBot: 2020 (Major waves through 2022)**
This primarily targeted D-Link routers and Hikvision cameras. It was unique for its highly aggressive scanning speed and its ability to quickly rotate Command & Control (C2) domains to avoid shutdown.

#### **VisualDoor: Early 2021**
Specifically targeting SonicWall SSL-VPN vulnerabilities, this marked a shift from attacking simple consumer gadgets to targeting corporate network security infrastructure.

#### **Corona: 2021**
Named during the global pandemic, this variant targeted unpatched home office equipment. It exploited the shift to remote work by targeting "Work-from-Home" (WFH) routers that lacked enterprise-grade security.

#### **V3G4: Late 2022/Early 2023**
One of the most advanced variants of its time, it utilized 13 different vulnerabilities simultaneously to maximize its infection rate. It features unique XOR encryption for its code, making it much harder for antivirus software to detect.

#### **Gayfemboy: Early 2024**
Despite the name, this variant became a serious persistent threat throughout 2024. It was notable for moving away from "burst" attacks to focus on maintaining long-term access to over 40 distinct groups of infected devices. It famously exploited zero-day vulnerabilities in industrial routers (CVE-2024-12856) to expand its reach.

#### **Aisuru (TurboMirai): Late 2024/2025**
Widely considered the apex of the Mirai lineage, this was discovered in August 2024 and grew to include over 300,000 compromised devices by early 2025. It's responsible for the record-breaking 31.4 Tbps DDoS attack mitigated by Cloudflare in February 2026. It uses AI-driven "precision flooding" to adapt its traffic patterns and bypass automated mitigation filters.

#### **Murdoc/Broadside: 2025**
A specialized variant appearing in early 2025 that targeted the maritime and logistics sectors. It specifically exploited vulnerabilities in TBK DVR systems (CVE-2024-3721) used on shipping vessels. This marked a significant shift where botnets began targeting specific industries rather than just a wide net of random consumer devices.

#### **Kimwolf & ShadowV2: Late 2025/Early 2026**
These're the most recent active strains as of early 2026. Kimwolf's notable for its massive scale (estimated 2+ million devices) and its use of advanced XOR encryption to hide its payloads. ShadowV2's a stealth variant that specifically targets 5G-connected IoT devices, leveraging their high bandwidth to launch devastatingly fast attacks.

### Evolution of Botnet Capabilities
Since the original source code leak, the Mirai structure's been upgraded with sophisticated features that allow it to bypass modern enterprise defenses.

#### **Command and Control (C2) Resilience**
- **P2P (Peer-to-Peer) Architecture**: Modern variants like Mozi and Aisuru have moved away from central servers. Instead, they utilize a distributed mesh where each "zombie" can relay commands to others, making it impossible to kill the botnet by taking down a single IP.
- **DGA (Domain Generation Algorithms)**: The malware uses a mathematical formula to generate hundreds of new rendezvous domains daily. The botmaster only needs to register one, while defenders are left playing hide-and-seek with thousands of blocked domains.
- **Stealthy Fallbacks**: New 2026 strains often use legitimate services like Cloudflare Tunnels or encrypted Telegram APIs as fallback C2 channels to blend in with normal web traffic.

#### **Persistence and Evasion Techniques**
- **Fileless Execution (In-Memory Only)**: To avoid detection by file-integrity monitors, many variants now run entirely in a device's RAM. While a reboot clears the infection, aggressive scanning usually re-infects the device within minutes.
- **Process Masquerading**: The malware often renames itself to look like legitimate system services (such as `systemd-logind` or `kworker`) to hide from basic process-inspection tools.
- **Anti-Analysis Modules**: Advanced versions like V3G4 check for virtualized environments or honeypots. If they detect they're being analyzed, they'll self-destruct or stay dormant.

#### **Exploitation and Lateral Movement**
- **N-Day Weaponization**: Botnet operators now automate the integration of new CVEs. A vulnerability published in the morning's often being actively scanned for by the afternoon.
- **Brute-Force Industrialization**: Moving beyond simple admin-admin lists, modern variants use AI-curated credential lists tailored to specific device manufacturers and models.
- **Worm-like Propagation**: Once a single IoT device on a home or office network's compromised, the malware scans the local network to find and infect other devices (lateral movement), bypassing the external firewall.

---

## Weak Authentication in Consumer IoT Devices
IoT devices are notorious for prioritizing comfort and convenience over security; from hard-coded, default passwords to a lack of MFA, the security gaps are huge. Flaws like these can help unauthorized devices access smart homes and pave the way for data theft, unauthorized control, or botnets. 

### **Common Vulnerabilities**
1. **Default or Hard-Coded Credentials**: This remains the top threat by far. These devices are frequently deployed with universal usernames and passwords like "admin." Some associated vulnerabilities include: 
- **Hard-Coded Backdoors**: Occasionally, these devices'll contain service or test accounts in the firmware that the user's unable to disable or change. This provides threat actors with a permanent entry point, as long as they can reverse engineer the hardware.
- **Credential Stuffing**: Because people have a tendency to reuse passwords, leaked account data could pave the way for an attacker to easily gain access. They use automated stuffing bots to get into things like camera feeds or door locks. 
- **Empty Passwords**: In some cases, "headless" devices (those without screens) are delivered with no password at all in the initial setup mode. This creates an opportunity for threat actors within Wi-Fi range to hijack the device before the owner completes the configuration. 

2. **Lack of Multi-Factor Authentication (MFA)**: Many services may require secondary codes, but the majority of IoT devices don't support MFA. Some specific risks include:
- **Static Session Hijacking**: With no MFA, once a threat actor steals a session cookie from your web browser or phone, they can remain logged into smart home accounts indefinitely without needing to reauthenticate. 
- **Account Takeover**: Once a threat actor makes one correct password guess, they gain full control. In 2024 and 2025, major breaches occurred when threat actors hijacked thousands of smart home accounts because there was no MFA. 

3. **Insecure Communication Protocols**: Authentication's only as strong as the path it travels; with no encryption, passwords and other sensitive data fly in cleartext. Some possible risks include:
- **Cleartext Transmission**: Many of these devices utilize the standard HTTP protocol for local communication. This means threat actors can sniff the traffic and see data in the clear. 
- **Replay Attacks**: Even when a password's encrypted, some devices are still vulnerable to replay attacks. A threat actor can capture the encrypted login message and replay it to the device later; the device sees the correct secret and grants access, even without proper authentication. 
- **Weak Password Reset Flows**: Some IoT apps have flawed links for the "Forgot Password" button that're unable to verify a user's identity properly. This creates an opportunity for a threat actor to trigger a reset and take the account over through a predictable security question or unencrypted email. 

### Mitigation
To efficiently protect IoT environments, it's important to employ defense-in-depth. You can't rely on a device on its own to be secure, and in 2026, mitigation's shifting from simple advice to automated, network-level enforcement. Here are some strategies that can help:
1. **Device-Level Hardening (The Manufacturer)**: The biggest mitigations begin with the manufacturer. Modern regulations, such as the US Cyber Trust Mark and UK PSTI Act, mandate several of these secure-by-design features, such as: 
- **Unique Per-Device Passwords**: Predictable default user and password combinations should no longer be used; they should be replaced by unique, random passwords on a sticker for each device. 
- **Secure Boot and Signed Firmware**: It's important to ensure a device only runs code that's been cryptographically signed by the manufacturer. This helps prevent Mirai-style malware from replacing legitimate system files. 
- **Hardware Security Modules (HSM)**: Dedicated secure element chips should be used to store encryption keys to prevent extraction, even if the device's stolen. 

2. **Network-Level Defenses (The Blue Team)**: Some potential strategies that someone in security can take to help protect these devices include: 
- **Network Segmentation (VLANs)**: All IoT devices should be placed on dedicated "guest" or "IoT" VLANs. This ensures that if smart devices are compromised, the threat actor can't move laterally to critical or sensitive systems. 
- **Micro-Segmentation and Least Privilege**: It's important to use firewalls to restrict devices to only the specific connections that're necessary. A smart fridge, for example, should be able to talk to the manufacturer's update server, but not to the printer or a random IP. 
- **Behavioral Analytics**: The use of AI-driven monitoring can establish a baseline for each device. If an IP camera that normally sends 10 MB of data to a local NVR suddenly starts sending 2 GB to an unrecognized IP, the system can detect and quarantine the device. 

3. **Proactive Management and Maintenance (The User)**: Today's security involves continuous processes instead of a "set-and-forget" approach. Some things that can be done include: 
- **Automated Patch Management**: Setting devices to auto-update by default's step one. For enterprise IoT, using a centralized management platform for pushing firmware updates can help push updates across thousands of devices at once. 
- **Disabling Unused Services**: Plug-and-Play (UPnP), Telnet, and web management interfaces should be turned off if they're not in use. Each port's an open door for a botnet scanner. 
- **Vulnerability Scanning**: Tools like OpenVAS or Nessus can be run against IoT devices to find if they're running outdated, vulnerable software.
