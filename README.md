<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ghatell/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that contained the string “tor” and discovered what looks like
the user “cybersentinel_92” downloaded a Tor installer, did something that resulted in many tor-related files
being copied to the desktop and a creation of a file called `tor-shopping-list.txt`.

These events began at `2025-03-28T15:10:16.2759262Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "sa-mde-test-2"
| where InitiatingProcessAccountName == "cybersentinel_92"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-03-28T15:10:16.2759262Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1237" alt="log1" src="https://github.com/user-attachments/assets/57a00c0f-41a2-4b22-946e-33acdf56577f" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcesssCommandLine` that contained the string “tor-browser-windows-x86_64-portable-14.0.8.exe”. Based on the logs returned on March 28, 2025, at 3:14:44
PM, on the device named `sa-mde-test-2`, the user `cybersentinel_92` initiated the execution of the file `tor-browser-windows-x86_64-portable-14.0.8.exe` located in the 'Downloads' folder. Using a command that triggered a silent installation ( /S).

Timestamp: `2025-03-28T15:14:44.434241Z`

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "sa-mde-test-2"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.8.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1253" alt="log2" src="https://github.com/user-attachments/assets/a41b79a7-bc3f-4d73-9924-5cdab645cfb6" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "cybersentinel_92" actually opened the TOR browser. There was evidence that they did open it at `2025-03-28T15:20:39.6314365Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "sa-mde-test-2"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1264" alt="log3" src="https://github.com/user-attachments/assets/68de082a-e090-49d1-b535-331374f10330" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the Tor browser was used to establish a connection using any of the known tor ports. At `2025-03-28T15:21:10.5474927Z`, the user 'cybersentinel_92' successfully connected to the IP address `94.23.148.66` over port `9000` using the Tor application located on their desktop. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "sa-mde-test-2"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9000", "9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| where InitiatingProcessFileName in ("tor.exe""firefox.exe")
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, FileName = InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1276" alt="log4" src="https://github.com/user-attachments/assets/2d5c2789-044c-4cfa-9ff8-c1d853e98650" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-28T15:10:16.2759262Z`
- **Event:** The user "cybersentinel_92" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\cybersentinel_92\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. File Modification – Tor Installation Files Extracted

- **Timestamp:** `2025-03-28T15:12:13.0000000Z`
- **Event:** The user "employee" modified multiple JavaScript validator files during what appears to be the unpacking or extraction phase of the Tor Browser setup.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Windows\SystemTemp\chrome_Unpacker_BeginUnzipped-*\edge*_.js`

### 3. Process Execution – Tor Browser Installation (Silent)

- **Timestamp:** `2025-03-28T15:14:44.434241Z`
- **Event:** The user "cybersentinel_92" executed the file tor-browser-windows-x86_64-portable-14.0.8.exe in silent mode, initiating a background installation of the Tor Browser.
- **Action:** Process creation detected.
- **Command:** tor-browser-windows-x86_64-portable-14.0.8.exe /S
- **File Path:** C:\Users\cyberSentinel_92\Downloads\tor-browser-windows-x86_64-portable-14.0.8.exe

### 4. Application Launch – Tor Browser Opened

- **Timestamp:** `2025-03-28T15:20:39.6314365Z`
- **Event:** The user "cybersentinel_92" launched the Tor Browser by executing tor.exe.
- **Action:** Process creation detected.
- **Command:** tor.exe
- **File Path:** C:\Users\cyberSentinel_92\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

### 5. Network Connection – Connection to Tor Network Established

- **Timestamp:** 2025-03-28T15:21:10.5474927Z
- **Event:** The user "cybersentinel_92" successfully connected to the Tor network at IP address 94.23.148.66 using port 9000.
- **Action:** Outbound network connection detected.
- **File Name:** tor.exe
- **File Path:** C:\Users\cyberSentinel_92\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

---

## Summary

On `March 28, 2025`, at `15:10 UTC`, user `cybersentinel 92` on device `sa-mde-test-2` initiated the download_and silent installation of the Tor browser. Over the next 10 minutes, numerous related files were unpacked and modified, indicating installation progress. At `15:20`, the user launched the Tor browser, and within a minute, the application successfully connected to the Tor network (port 9000), confirming it was actively in use. This sequence of events shows a clear, intentional use of the Tor browser by the user. The presence of multiple tor-related processes and a successful connection to the Tor network strongly suggests the user was attempting to anonymize internet activity.

---

## Response Taken

TOR usage was confirmed on endpoint `sa-mde-test-2` by the user `cybersentinel_92`. The device was isolated and the user's direct manager was notified.

---
