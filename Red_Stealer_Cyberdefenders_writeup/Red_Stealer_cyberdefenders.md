# Writeup: CyberDefenders | RedStealer by CbrKrtek

## 🚩 Challenge Info
*   **Platform:** [CyberDefenders](https://cyberdefenders.org/)
*   **Challenge:** [RedStealer](https://cyberdefenders.org/blueteam-ctf-challenges/red-stealer/)
*   **Difficulty:** Easy
*   **Category:** Threat Inteligence
*   **Tools:**  `VirusTotal` `MalwareBazaar` `ThreatFox` `Mittre Attack`

## Scenario
You are part of the Threat Intelligence team in the SOC (Security Operations Center). An executable file has been discovered on a colleague's computer, and it's suspected to be linked to a Command and Control (C2) server, indicating a potential malware infection.
Your task is to investigate this executable by analyzing its hash. The goal is to gather and analyze data beneficial to other SOC members, including the Incident Response team, to respond to this suspicious behavior efficiently.
**Lab files**: Zip archive in which we have a .txt file in this file we see that: 
SHA256: 248FCC901AFF4E4B4C48C91E4D78A939BF681C9A1BC24ADDC3551B32768F907B
## Q1
Categorizing malware enables a quicker and clearer understanding of its unique behaviors and attack vectors. What category has Microsoft identified for that malware in VirusTotal?
## Solution(Q1)
Let's write this SHA256 hash into a virustotal.
<img width="1919" height="826" alt="screen_Q1_Red_stealer" src="https://github.com/user-attachments/assets/0a2ce6c3-a591-48a3-85f2-5f325ad1641f" />
then click on "Detection" and find "Microsoft" in a column, which called "Security vendors' analysis".
<img width="1305" height="50" alt="screen_Q1_microsoft_trojan" src="https://github.com/user-attachments/assets/cfdd76f0-be99-4e95-b929-bd00dd60cf42" />
We found that and than in the 2-nd column we see: "Trojan:Win32/Redline!rfn". It means that Microsoft identifies the file as a Redline Trojan. And let's pay attention to the "!rfn". It's a suffix, indicating a detection option (often meaning “Cloud detection” or “ML detection”).So, the answer is **Trojan**.
## Q2
Clearly identifying the name of the malware file improves communication among the SOC team. What is the file name associated with this malware?
## Solution(Q2)
In this question we need to look at the main board (I mean that board):  
<img width="1384" height="218" alt="screen_Q2_Red_stealer" src="https://github.com/user-attachments/assets/ef0db18b-dda9-4b13-a5cd-a5a71194e810" />
The file name is highlighted in yellow color.
_Additionally we need to understand, that the expansion of file is "EXE.MUI"_.
Why i said about that? Because when user will see a file WEXTRACT.EXE (.MUI will be ignored because .MUI files contain localized resources (texts, interface elements) for programs and the system itself in different languages. 
The answer is **Wextract**
## Q3
Knowing the exact timestamp of when the malware was first observed can help prioritize response actions. Newly detected malware may require urgent containment and eradication compared to older, well-documented threats. What is the UTC timestamp of the malware's first submission to VirusTotal?
## Solution
<img width="1308" height="691" alt="screen_Q3_Red_stealer" src="https://github.com/user-attachments/assets/c0d076b4-2757-4796-b327-1dc24f134d43" />
In this case you should choose "Details" in VirusTotal and then check history. Then check first Submission.
The answer is **2023-10-06 04:41**.

## Q4
Understanding the techniques used by malware helps in strategic security planning. What is the MITRE ATT&CK technique ID for the malware's data collection from the system before exfiltration?
## Solution
Let's move to a Mittre Attack and check.
<img width="1900" height="762" alt="Q4_red_stealer" src="https://github.com/user-attachments/assets/66e71925-129b-4d86-a6e6-95346ddd67c2" />
We must to check a section "Collection" because we know from the task that was collection from system before exfiltration. Ok, then find a "Data from Local System", click and check the ID in a picture.

<img width="1394" height="904" alt="Mittre_1005" src="https://github.com/user-attachments/assets/d1e531d9-7b3c-49f5-afa1-393e3fc23e74" />
I will proof later, that this tactic is relevant to our situation.
The answer is **T1005**.
### _What if the task didn't specify that the malware collected data from the system before exfiltration?_
In that case let's check file system actions in Virustotal.
<img width="1448" height="775" alt="Q4_exception" src="https://github.com/user-attachments/assets/8596e0e1-afe8-4716-ab82-a0afdd8de72b" />

Then we see that a malware exfiltrated all from a disc C (in a screen it's a part). So I proved that this tactic is relevant to a malware.
## Q5
Following execution, which social media-related domain names did the malware resolve via DNS queries?
## Solution
Let's move into "Behaviour" and check DNS resolutions
<img width="908" height="771" alt="Social_media_red_stealer" src="https://github.com/user-attachments/assets/c15fad47-af77-42d6-8050-b5352e9a4a8c" />
Than we see a facebook social media. I put it in a red box. The answer is **facebook**.
## Q6
Once the malicious IP addresses are identified, network security devices such as firewalls can be configured to block traffic to and from these addresses. Can you provide the IP address and destination port the malware communicates with?
## Solution
Let's move to "Behaviour" and here in a section "Memory Pattern Ips" we will see this:
<img width="1314" height="767" alt="ip red" src="https://github.com/user-attachments/assets/1c83f6c9-fc1f-4049-ab7b-a58948571a91" />

Here we see that ip: 77.91.124.55 is detected by ZenBox and C2AE. So, we can say that this ip is malicious. The answer is **77.91.124.55**,but we need to write a port. If scroll down, we will see this ip with it's port. Then the final answer is **77.91.124.55:19071**.
## Q7
YARA rules are designed to identify specific malware patterns and behaviors. Using MalwareBazaar, what's the name of the YARA rule created by "Varp0s" that detects the identified malware?
## Solution
In that case we need to search https://bazaar.abuse.ch/sample/248fcc901aff4e4b4c48c91e4d78a939bf681c9a1bc24addc3551b32768f907b/
*here 248fcc901aff4e4b4c48c91e4d78a939bf681c9a1bc24addc3551b32768f907b is our SHA-256 hash*.
Then let's scroll down and check YARA-rules:
<img width="1485" height="902" alt="Q7_YARA_rule" src="https://github.com/user-attachments/assets/1d15c260-f344-47d3-9adf-a8decedd3a82" />

Here we see a rule name:"detect_Redline_Stealer".
The answer is **detect_Redline_Stealer**.
## Q8
Understanding which malware families are targeting the organization helps in strategic security planning for the future and prioritizing resources based on the threat. Can you provide the different malware alias associated with the malicious IP address according to ThreatFox?
## Solution
Here we need to search a Redline stealer in a ThreatFox
<img width="988" height="398" alt="threat_fox" src="https://github.com/user-attachments/assets/a860a0b3-582c-45ea-b72a-2c2da290583d" />
and in the red box we see a Malware alias.
The answer is **RECORDSTEALER**
## Q9
By identifying the malware's imported DLLs, we can configure security tools to monitor for the loading or unusual usage of these specific DLLs. Can you provide the DLL utilized by the malware for privilege escalation?
## Solution
Let's return to a Virustotal and in a Details we can find a section "Imports".
<img width="915" height="660" alt="Q10" src="https://github.com/user-attachments/assets/f1b7e5c5-0a95-4d31-a71b-8d1aa2de0344" />
Then we can check each dll. If check ADVAPI32.dll here we can see that this dll adjusts token privileges. Then the answer is **ADVAPI32.dll**.
# 🏆 Key Flags
| Question | Answer |
| :--- | :--- |
| **Q1**| `Trojan` |
| **Q2** | `Wextract` |
| **Q3** | `2023-10-06 04:41` |
| **Q4** | `T1005` |
| **Q5** | `facebook.com` |
| **Q6** | `77.91.124.55:19071` |
| **Q7** | `detect_Redline_Stealer` |
| **Q8** | `RECORDSTEALER` |
| **Q9** | `ADVAPI32.dll` |
## 📚 Summary & Insights
This was my first writeup, and I really appreciate that you read it all the way through. This writup is good for a beginners in cybersecurity, malware analyzing, SOC-analytics. 
