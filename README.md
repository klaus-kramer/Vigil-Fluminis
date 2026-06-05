# Vigil-Fluminis - Guardian of the river    
    
Analyse and manage firewall rules for Windows. A check against various criteria to generate a "suspicious" score that can assist the user during evaluation.    
Built with C++/Qt. No installer, just unzip the Release and run.

# Usage:    
Main Window:    
Top left switch firewall and firewallservice on/off.    
Top right: the rulestatistics    
app-signature- and connection-statistics should started manually    
Left: The buttons to start "Analyse rules", "Analyse apps", "Analyse connections",
"Options" and "Help"    

![Vigil Fluminis](Vigil_Fluminis_256.png)

# criteria for suspicious-score:    
Online access was deliberately forgone—which, naturally, meant sacrificing up-to-date information.

- ports(resources/threads.json): The ports represent general security knowledge drawn from established sources    
  
- malwarenames (resources/known_malware.json): genuine, documented malware families (ransomware, botnets, worms, stealers, miners, rootkits)    

- ip(resources/ip:reputation.json): Safe: known legitimate services    
Suspicious – known malicious networks, networks that are frequently abused for Command & Control
    
- suspicions directories:
Temp – %TEMP% (forexample C:\Users\...\AppData\Local\Temp)    
Downloads    
AppData (Local) – forexample C:\Users\...\AppData\Local    
AppData (Roaming) – forexample C:\Users\...\AppData\Roaming    

- signed / unsigned apps

- fileage from timestamp:
< 15 days and > 4 years    

# Please note:
Since connections required for proper functionality may also be flagged as potentially suspicious (e.g., based on IP/port), please exercise caution and do not delete any connection until you are certain that it is not required. As a precautionary measure, a backup of the rules is created in the "backups" directory.    
