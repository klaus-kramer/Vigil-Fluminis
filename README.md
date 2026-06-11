# Vigil-Fluminis - Guardian of the river    
    
Windows Firewall Analysis. A check against various criteria to generate a "suspicious" score that can assist the user during evaluation.    
Built with C++/Qt. No installer, just unzip the Release and run.

## Features
- Firewall rule analysis with risk scoring    
- Active connection monitoring with IP reputation checks    
- App signature verification
- ask an locally running AI for evaluation of the rule/app/connection    
- Trojan detection test – detects data exchange during user input (admin req.)    

# Usage:    
Main Window:    
Top left switch firewall and firewallservice on/off.    
Top right: the rulestatistics    
app-signature- and connection-statistics should started manually    
Left: The buttons to start "Analyse rules", "Analyse apps", "Analyse connections",    
"Trojan test with admin", "Options" and "Help"    
now in top menu of rules/app/connection window is a button "Ask AI" - select and ask     

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

# Trojan test:
The "Trojan test with admin" button launches a simple Trojan-keylogger-test that identifies programs transmitting data outgoing while the user is typing; this requires administrator privileges. Naturally, this method would not detect Trojans that buffer data rather than transmitting it immediately. Users can easily test this by visiting a search engine, starting the test, typing something into the search engine (e.g., www.google.com), and stopping the test—at which point the browser should appear in the results.    

# Ask AI:    
- First you have to download an AI suggestion Phi-3-mini-4k-instruct-q4    
[downloadlink phi-3-mini-4k](https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf)
and put it for example in the models-directory. qwen2.5-7b-q4_k_m-imat would also work for example.    
- in Vigil Fluminis open options->AI settings->modelfile and select the model
- now it should work if you select an entry in rules/apps/connections and klick "Ask AI" in menu
- the AI runs locally on your computer without connection to internet    
