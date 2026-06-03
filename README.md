# Vigil-Fluminis
    
Analyse and manage firewall rules for Windows. A check against various criteria to generate a "suspicious" score that can assist the user during evaluation.    

# Usage:    
Main Window:    
Top left the user can switch firewall and firewallservice on/off.    
Top right: the rulestatistics    
Left: The buttons to start "Analyse rules", "Analyse apps", "Analyse connections",
"Options" and "Help"    

# criteria for suspicious-score:    
Online access was deliberately forgone—which, naturally, meant sacrificing up-to-date information.

- ports(resources/threads.json): The ports represent general security knowledge drawn from established    sources: Microsoft documentation, OWASP, SANS, CISA recommendations, and decades of exploit observation    (e.g., RDP = most frequent brute-force target; SMB 445 = EternalBlue/WannaCry; RPC 135 = remote     exploitation). There is no single "source"—rather, it represents the established consensus regarding     services that should never be exposed to the Internet without protection.    
  
- malwarenames (resources/known_malware.json): genuine, documented malware families (ransomware, banking    Trojans, RATs, botnets, worms, stealers, miners, rootkits). Sources include MalwareBazaar, Microsoft    Threat Intelligence, CISA KEV, and SANS Top Malware.   

- ip(resources/ip:reputation.json): Safe (54 CIDRs): known legitimate services – Google/Gmail/DNS,    Cloudflare, Microsoft, Amazon AWS, GitHub, GitLab, Stack Overflow, etc.    
Suspicious – Spamhaus DROP (46 CIDRs): A curated subset of the Spamhaus DROP List (Don't Route Or Peer) –  known malicious networks.    
Cloud Hosting (68 CIDRs): Published IP ranges from DigitalOcean and Hetzner (labeled as "(C2 risk)"    because these networks are frequently abused for Command & Control).    

- suspicions directories:
Temp – %TEMP% (forexample C:\Users\...\AppData\Local\Temp)    
Downloads    
AppData (Local) – forexample C:\Users\...\AppData\Local    
AppData (Roaming) – forexample C:\Users\...\AppData\Roaming    

- fileage from timestamp:
< 15 days and > 4 years    

# Questions/Suggestions:
please open an issue with question or suggestion at start of the title    

