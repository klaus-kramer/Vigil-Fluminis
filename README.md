# Vigil-Fluminis - Guardian of the river    
    
Analyse and manage firewall rules for Windows. A check against various criteria to generate a "suspicious" score that can assist the user during evaluation.    

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

- ip(resources/ip:reputation.json): Safe (54 CIDRs): known legitimate services    
Suspicious – known malicious networks, networks that are frequently abused for Command & Control
    
- suspicions directories:
Temp – %TEMP% (forexample C:\Users\...\AppData\Local\Temp)    
Downloads    
AppData (Local) – forexample C:\Users\...\AppData\Local    
AppData (Roaming) – forexample C:\Users\...\AppData\Roaming    

- fileage from timestamp:
< 15 days and > 4 years    

