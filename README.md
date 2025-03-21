Threat Hunt Report (Unauthorized TOR Usage)
Detection of Unauthorized TOR Browser Installation and Use on Workstation: _______________
Example Scenario:
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

High-Level TOR related IoC Discovery Plan:
Check DeviceFileEvents for any tor(.exe) or firefox(.exe) file events
Check DeviceProcessEvents for any signs of installation or usage
Check DeviceNetworkEvents for any signs of outgoing connections over known TOR ports

Steps Taken
The initial search showed that the account “lab user” had appeared to have downloaded a tor installer and created a file called “tor shopping list.txt” on the desktop. The malicious events began at exactly 13:30 GMT on the 20th March 2025.
Query used to locate events:
image
4. Searched the DeviceNetworkEvents Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At 2024-11-08T22:18:01.1246358Z, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address 176.198.159.33 on port 9001. The connection was initiated by the process tor.exe, located in the folder c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe. There were a couple of other connections to sites over port 443.

Query used

DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
image

___


Next I searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.0.1.exe”. What i found was that on 20 Mar 2025 at 13:35:04 the account “lab user” ran this command combined with “/S” to silently trigger a silent installation of Tor.

Query used 

DeviceProcessEvents
| where DeviceName == "kieranvm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

___


Further searches into the DeviceProcessEvents focused events showing FileNames that were “tor.exe” or “firefox.exe”. Evidence from this pointed to an initial “firefox.exe” file being opened by “lab-user” at 13:37, whilst this may seem related to firefox when I compared the SHA256 hash with one from a legitimate updated firefox version they didn't match suggesting something else was being maliciously installed. The logs also suggest several other files were opened in a similar manner


Query used 

DeviceProcessEvents
| where DeviceName == "kieranvm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 


___


I then searched for ports often used by Tor and found 3 connections were established on the “kieranvm” device by the “lab user” to unknown IP addresses in “127.0.0.1”, and “46.228.199.128”.

Query used

DeviceNetworkEvents
| where DeviceName == "kieranvm"
| where InitiatingProcessAccountName !in ("system", "network service")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl



Chronological Event Timeline

1. File Download - TOR Installer

Timestamp: 2024-11-08T22:14:48.6065231Z
Event: The user "employee" downloaded a file named tor-browser-windows-x86_64-portable-14.0.1.exe to the Downloads folder.
Action: File download detected.
File Path: C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe
2. Process Execution - TOR Browser Installation

Timestamp: 2024-11-08T22:16:47.4484567Z
Event: The user "employee" executed the file tor-browser-windows-x86_64-portable-14.0.1.exe in silent mode, initiating a background installation of the TOR Browser.
Action: Process creation detected.
Command: tor-browser-windows-x86_64-portable-14.0.1.exe /S
File Path: C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe
3. Process Execution - TOR Browser Launch

Timestamp: 2024-11-08T22:17:21.6357935Z
Event: User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as firefox.exe and tor.exe, were also created, indicating that the browser launched successfully.
Action: Process creation of TOR browser-related executables detected.
File Path: C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
4. Network Connection - TOR Network

Timestamp: 2024-11-08T22:18:01.1246358Z
Event: A network connection to IP 176.198.159.33 on port 9001 by user "employee" was established using tor.exe, confirming TOR browser network activity.
Action: Connection success.
Process: tor.exe
File Path: c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe
5. Additional Network Connections - TOR Browser Activity

Timestamps:
2024-11-08T22:18:08Z - Connected to 194.164.169.85 on port 443.
2024-11-08T22:18:16Z - Local connection to 127.0.0.1 on port 9150.
Event: Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
Action: Multiple successful connections detected.
6. File Creation - TOR Shopping List

Timestamp: 2024-11-08T22:27:19.7259964Z
Event: The user "employee" created a file named tor-shopping-list.txt on the desktop, potentially indicating a list or notes related to their TOR browser activities.
Action: File creation detected.
File Path: C:\Users\employee\Desktop\tor-shopping-list.txt
Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named tor-shopping-list.txt. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

Response Taken

TOR usage was confirmed on the endpoint threat-hunt-lab by the user employee. The device was isolated, and the user's direct manager was notified.
