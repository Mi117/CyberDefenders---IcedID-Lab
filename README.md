# CyberDefenders---IcedID-Lab

CyberDefenders —  IcedID Lab Walkthrough

INTRO: 

This challenge, inspired by the real-world IceID banking Trojan, puts you in the shoes of a blue team analyst tasked with unraveling a sophisticated cyberattack. Prepare to sharpen your skills in network traffic analysis, memory forensics, and reverse engineering as you uncover the secrets hidden within this insidious malware. Your mission: dissect the attack, identify key indicators of compromise (IOCs), and ultimately, neutralize the threat. Are you ready to face the IceID challenge and prove your blue team prowess? Let the investigation begin!

TOOLS AND RESOURCES USED:

- VIRUS TOTAL [https://www.virustotal.com/gui/]: for identifying details about the malware, by submitting the file(s) hashes to get comprehensive scan results and analysis.
- MITRE ATT&CK [https://attack.mitre.org/]: a knowledge base of tactics and techniques matrix to help providing a comprehensive framework of threat actors' tactics, techniques, and procedures.

SCENARIO:

A cyber threat group was identified for initiating widespread phishing campaigns to distribute further malicious payloads. The most frequently encountered payloads were IcedID. You have been given a hash of an IcedID sample to analyze and monitor the activities of this advanced persistent threat (APT) group.

[Link to the challenge: https://cyberdefenders.org/blueteam-ctf-challenges/icedid/ ]

----------------

WALKTHROUGH:

Q1) What is the name of the file associated with the given hash?

Heading onto Virus total with the file hash we can see. on the Details section, the names associated with the file (document-1982481273.xlsm)

![q1](https://github.com/user-attachments/assets/823464d6-8eb0-4eab-b2c7-46afacb2195a)

Q2) Can you identify the filename of the GIF file that was deployed?

Let's head to the Relations tab, and we should look at for a .gif file with repetitive requests. 

![q2](https://github.com/user-attachments/assets/cb68b3aa-d6dc-4d2e-be30-c5e15fdddd98)

Here we can fine several, but only one stands out with the current rate of 12/96 detections (https://columbia.aula-web.net/ds/3003.gif)

Q3) How many domains does the malware look to download the additional payload file in Q2?

By looking at the Relations tab we can determine the domains contacted by the malware to download the 3003.gif payload. A total of 5 distinct domains are identified:

![q3](https://github.com/user-attachments/assets/5dc507bc-b11e-4d94-96a9-7022208c706d)

- https://tajushariya.com/ds/3003.gif
- https://agenbolatermurah.com/ds/3003.gif
- https://metaflip.io/ds/3003.gif
- https://partsapp.com.br/ds/3003.gif
- https://columbia.aula-web.net/ds/3003.gif


Q4) From the domains mentioned in Q3, a DNS registrar was predominantly used by the threat actor to host their harmful content, enabling the malware's functionality. Can you specify the Registrar INC?

The Contacted Domains section in VirusTotal reveals that these domains were registered through NameCheap.

![q4](https://github.com/user-attachments/assets/bc3f4621-a081-46d5-9cba-2c0180dbcb5a)

Threat actors frequently select registrars that offer anonymity and ease of registration, enabling the rapid deployment of malicious infrastructure.

Q5) Could you specify the threat actor linked to the sample provided?

Let's do a deeper research on the MitreAtt&ck website to see the threat actors linked to this IceID sample. 

![q5-1](https://github.com/user-attachments/assets/6b32b884-f065-42b8-ba75-9972e439e14c)

We find that the malware is used by the group TA551, also known as "Gold Cabin"

![q5-2](https://github.com/user-attachments/assets/48da8d14-e588-42d0-ade8-9bc0ce44da86)

Q6) In the Execution phase, what function does the malware employ to fetch extra payloads onto the system?

The malware's execution phase can be seen in the MitreAtt&ck section of VirusTotal as part of the Execution tactics TA0002 > Exploitation for Client Execution T1203 [UrlDownloadToFile]. In our case the specific answer is UrlDownloadToFileA.

![q6](https://github.com/user-attachments/assets/517548e7-82b0-4329-81a0-e8a22799e521)

(for more details, please refer to the MitreAtta&ck website: https://attack.mitre.org/tactics/TA0002/ ].

The primary purpose of using [URLDownloadToFileA] in malware is to download malicious payloads from a remote server. This function allows the malware to retrieve additional components, such as executables, dynamic-link libraries (DLLs), or configuration files, which are necessary for the malware to perform its malicious activities.
Once the file is downloaded, the malware can execute it using functions like WinExec or ShellExecuteA, or load it into memory for further exploitation. Some antivirus programs flag URLDownloadToFile as suspicious because it is often used in Trojan downloaders

------------

CONCLUSIONS:

In conclusion, the IceID CTF challenge has been an invaluable journey into the complex world of malware analysis and incident response. This exercise underscores the critical role of skilled blue team analysts in defending against sophisticated threats like the IceID banking Trojan. 
Successfully dissecting the attack, identifying key IOCs, and understanding the adversary's tactics wouldn't have been possible without leveraging the MITRE ATT&CK framework. ATT&CK provided a crucial common language and structured knowledge base to classify and understand the observed behaviors, linking them to known adversarial techniques. 
This experience has not only honed my technical abilities but also reinforced the importance of continuous learning and adaptation in the ever-evolving cybersecurity landscape. The knowledge gained from this challenge will undoubtedly empower me to tackle future security incidents with greater confidence and effectiveness, contributing to a more resilient and secure digital environment.

Future Directions This challenge has reinforced the importance of continuous learning and hands-on experience in cybersecurity. Moving forward, I aim to apply these skills in real-world scenarios, contributing to more effective threat detection and mitigation strategies.

Acknowledgments I would like to thank CyberDefenders for providing this engaging and educational challenge. The experience has been invaluable in sharpening my skills in malware analysis and incident response.

I hope you found this walkthrough insightful as well! If you found this content helpful, please consider giving it a clap! Your feedback is invaluable and motivates me to continue supporting your journey in the cybersecurity community. Remember, LET'S ALL BE MORE SECURE TOGETHER! For more insights and updates on cybersecurity analysis, follow me on Substack! [https://substack.com/@atlasprotect?r=1f5xo4&utm_campaign=profile&utm_medium=profile-page].
