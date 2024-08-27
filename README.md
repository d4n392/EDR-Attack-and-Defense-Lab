# EDR-Attack-and-Defense-Lab

In this foundational SOC Home Lab I spun up a Win10 vm as my victim client and disabled Windows Defender EDR. Set up a C2 framework using Sliver for emulating threat-actor behavior by crafting my very own malicious payload. Threw attacks, caught the detections and watched the malicious traffic. Set up automated D&R rules to mitigate these attacks.

Eric Capuano's Guide: https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro?utm_campaign=post&utm_medium=web

### Setup:

First I spun up both virtual machines. The attack machine will run on Ubuntu Server, and the endpoint will be running Windows 11. In order for this lab to work smoothly I turned off all the Windows Security solutions (Virus & threat protection, Microsoft Defender Firewall, etc.) on the Windows 11 VM, making it my vulnerable victim machine. I am also going to be installing Sliver on the Ubuntu machine as my primary attack tool, and setting up LimaCharlie on the Windows machine as an EDR solution. LimaCharlie will have a sensor linked to the Windows machine, and will be importing sysmon logs.

### Skills Learned

- Advanced understanding of EDR concepts and practical application.
- Proficiency in analyzing and interpreting network telemetry.
- Ability to generate, deploy, transfer, and execute a command-and-control (C2) payload on the Windows endpoint using Sliver.
- Enhanced knowledge of Windows commands to gather information and assess system privileges.
- Familiarization with normal vs. anomalous activity to enhance threat detection capabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.
- Understanding the process of performing hash scans on sites like VirusTotal to identify known malware. As well as understanding false negative results when dealing with a newly crafted payload.
- Detection rule creation and response implementation on a SecOps Cloud Platform such as LimaCharlie.


### Tools Used

- LimaCharlie EDR for endpoint detection and response capabilities,
monitoring and capturing telemetry, creating and applying detection rules.
- Sysmon integrated with LimaCharlie for detailed network logging and event capture on the Windows endpoint.
- VirusTotal used for scanning and analyzing the hash of executables to identify known malware.
- Sliver C2 Server for crafting and deploying a malicious payload.

## Steps

*Ref 1: Windows Security controls off*

![image](https://github.com/user-attachments/assets/415b034b-db82-4da7-bdf9-88b55b2f52c3)
![image](https://github.com/user-attachments/assets/9d6597e1-a266-4ab8-8852-72c1754aeede)















