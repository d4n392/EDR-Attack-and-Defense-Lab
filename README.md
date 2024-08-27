# EDR-Attack-and-Defense-Lab

In this foundational SOC Home Lab I spun up a Win10 vm as my victim client and disabled Windows Defender EDR. Set up a C2 framework using Sliver for emulating threat-actor behavior by crafting my very own malicious payload. Threw attacks, caught the detections and watched the malicious traffic. Set up automated D&R rules to mitigate these attacks.

Eric Capuano's Guide: https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro?utm_campaign=post&utm_medium=web

### Setup:

Configured and set up Ubuntu Server and Windows 11 virtual machines for attack and defense roles.
Installed and configured Sliver C2 framework on the Ubuntu machine.
Deployed and set up LimaCharlie EDR on the Windows machine, including integrating Sysmon for enhanced logging.
Payload Creation and Deployment:

Generated and deployed a command-and-control (C2) payload using Sliver.
Transferred and executed the payload on the Windows endpoint.
Command and Control Operations:

Established and managed a C2 session between the attack and endpoint machines.
Executed basic commands on the compromised Windows machine to gather information and assess system privileges.
Endpoint Detection and Response:

Utilized LimaCharlie to monitor and analyze telemetry from the Windows endpoint.
Identified and analyzed C2 payload activity and network connections through LimaCharlie.
Threat Analysis and Detection:

Performed hash scans of payloads with VirusTotal for threat identification.
Detected and analyzed sensitive processes and other suspicious activities on the endpoint.
Rule Creation and Implementation:

Developed and implemented detection rules in LimaCharlie to identify and respond to specific attack behaviors.
Simulated credential theft and ransomware attacks to test and refine detection and blocking rules.
Attack Simulation and Mitigation:

Simulated various attack scenarios, including credential dumping and ransomware attempts.
Used LimaCharlie to create and apply rules to detect and block simulated attacks, ensuring effective defense mechanisms.
Security Telemetry Analysis:


Familiarized with normal vs. anomalous activity to enhance threat detection capabilities.

This lab provided hands-on experience in attack simulation, endpoint monitoring, and rule-based defense strategies, enhancing skills in both offensive and defensive cybersecurity practices.

### Skills Learned
[Bullet Points - Remove this afterwards]

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used
[Bullet Points - Remove this afterwards]
- LimaCharlie EDR for endpoint detection and response capabilities,
monitoring and capturing telemetry, creating and applying detection rules.
- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
- Telemetry generation tools to create realistic network traffic and attack scenarios.

## Tools:

Sliver C2 Framework:
Used for generating and managing command-and-control (C2) payloads.
Facilitates establishing and controlling sessions on compromised systems.
LimaCharlie EDR:
Provides endpoint detection and response capabilities.
Monitors and captures telemetry such as process activity, network connections, and file system changes.
Allows for the creation and application of detection rules.
Ubuntu Server:
Hosts the Sliver C2 server.
Used for launching attacks and managing the C2 framework.
Windows 11:
Acts as the target system for deploying and executing C2 payloads.
Monitored using LimaCharlie for detecting and analyzing the impact of attacks.
Sysmon:
Integrated with LimaCharlie for detailed logging and event capture on the Windows endpoint.
VirusTotal:
Used for scanning and analyzing the hash of executables to identify known malware.
These tools collectively provide a comprehensive environment for simulating cyber attacks, monitoring endpoints, and developing detection and response strategies.

Skills Learned in the EDR Home Lab: Attack and Defense

Virtual Machine Setup:

Configured and set up Ubuntu Server and Windows 11 virtual machines for attack and defense roles.
Installed and configured Sliver C2 framework on the Ubuntu machine.
Deployed and set up LimaCharlie EDR on the Windows machine, including integrating Sysmon for enhanced logging.
Payload Creation and Deployment:

Generated and deployed a command-and-control (C2) payload using Sliver.
Transferred and executed the payload on the Windows endpoint.
Command and Control Operations:

Established and managed a C2 session between the attack and endpoint machines.
Executed basic commands on the compromised Windows machine to gather information and assess system privileges.
Endpoint Detection and Response:

Utilized LimaCharlie to monitor and analyze telemetry from the Windows endpoint.
Identified and analyzed C2 payload activity and network connections through LimaCharlie.
Threat Analysis and Detection:

Performed hash scans of payloads with VirusTotal for threat identification.
Detected and analyzed sensitive processes and other suspicious activities on the endpoint.
Rule Creation and Implementation:

Developed and implemented detection rules in LimaCharlie to identify and respond to specific attack behaviors.
Simulated credential theft and ransomware attacks to test and refine detection and blocking rules.
Attack Simulation and Mitigation:

Simulated various attack scenarios, including credential dumping and ransomware attempts.
Used LimaCharlie to create and apply rules to detect and block simulated attacks, ensuring effective defense mechanisms.
Security Telemetry Analysis:

Analyzed security event logs and telemetry data to understand attack impacts and improve response strategies.
Familiarized with normal vs. anomalous activity to enhance threat detection capabilities.
This lab provided hands-on experience in attack simulation, endpoint monitoring, and rule-based defense strategies, enhancing skills in both offensive and defensive cybersecurity practices.






You said:
What about a bulleted list of the tools learned
ChatGPT said:
ChatGPT
Tools Learned in the EDR Home Lab: Attack and Defense

Sliver C2 Framework:

Used for generating and managing command-and-control (C2) payloads.
Facilitates establishing and controlling sessions on compromised systems.
LimaCharlie EDR:

Provides endpoint detection and response capabilities.
Monitors and captures telemetry such as process activity, network connections, and file system changes.
Allows for the creation and application of detection rules.
Ubuntu Server:

Hosts the Sliver C2 server.
Used for launching attacks and managing the C2 framework.
Windows 11:

Acts as the target system for deploying and executing C2 payloads.
Monitored using LimaCharlie for detecting and analyzing the impact of attacks.
Sysmon:

Integrated with LimaCharlie for detailed logging and event capture on the Windows endpoint.
VirusTotal:

Used for scanning and analyzing the hash of executables to identify known malware.
These tools collectively provide a comprehensive environment for simulating cyber attacks, monitoring endpoints, and developing detection and response strategies.




## Steps
drag & drop screenshots here or use imgur and reference them using imgsrc

Every screenshot should have some text explaining what the screenshot is about.

Example below.

*Ref 1: Network Diagram*
















