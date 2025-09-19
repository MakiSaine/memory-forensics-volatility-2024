# Malware Memory Analysis (Volatility) – 2024

This project analyzes a memory dump to extract process information, check for network activity, and detect suspicious behavior using **Volatility 3** and **YARA rules**.

---

## Table of Contents

- [Overview](#overview)
- [Objectives](#objectives)
- [Tools and Setup](#tools-and-setup)
- [Process Analysis (pslist)](#process-analysis-pslist)
- [Network Analysis (netscan)](#network-analysis-netscan)
- [YARA Rule Creation & Scan](#yara-rule-creation--scan)
- [Key Findings](#key-findings)
- [Reflection](#reflection)

---

## Overview

In this lab, a memory dump (`mem.raw`) was analyzed using **Volatility 3**.  
The goal was to identify the process tree for `wzdu35.exe`, check for network connections, and detect the process in memory using a custom YARA rule.

---

## Objectives

- Extract process and parent process IDs (PID & PPID)
- Check for active network connections in the dump
- Write a custom **YARA rule** to detect the process in memory
- Verify YARA hits on the correct PID without false positives

---

## Tools and Setup

- **Volatility 3 Framework** – memory forensics
- **Python 3** – running Volatility plugins
- **Nano** – for creating the YARA rule file

---

## Process Analysis (pslist)

Command used:

```bash
python3 vol.py -f mem.raw windows.pslist
```

**Result:**  
The process `wzdu35.exe` was found with **PID 2312** and **PPID 288**.

![Process List Screenshot](./screenshots/volatility_pslist.png)

---

## Network Analysis (netscan)

Command used:

```bash
python3 vol.py -f mem.raw windows.netscan
```

**Result:**  
No active network connections were found in the memory dump at the time of capture.

![Network Scan Screenshot](./screenshots/volatility_netscan.png)

---

## YARA Rule Creation & Scan

A custom YARA rule was created with **nano**:

```yara
rule analyse_wzdu35 {
  strings:
    $string1 = "wzdu35.exe"
  condition:
    $string1
}
```

Saved as `analyse_wzdu35.yar`.

Then, Volatility’s `yarascan` plugin was used to scan the memory:

```bash
python3 vol.py -f mem.raw windows.vadyarascan.VadYaraScan --yara-file analyse_wzdu35.yar
```

**Result:**  
Multiple matches were found in **PID 2312** and one match in **PID 288**.

![YARA Scan Screenshot](./screenshots/volatility_yarascan.png)

---

## Key Findings

- `wzdu35.exe` was active in memory with PID 2312 and PPID 288.
- No network connections were established at the time of memory capture.
- The custom YARA rule successfully identified the process in memory.
- The detection was accurate and produced no false positives.

---

## Reflection

This exercise deepened my understanding of **memory forensics** and **process analysis**.  
By using Volatility and YARA together, I learned how to identify malicious processes in a memory dump and confirm their presence with a signature based approach.  
The fact that no network connections were found suggests that the process might have been dormant or not communicating externally at the time of capture.  
This highlights the importance of correlating memory analysis with network data to get a full picture of system activity.

---

## Author

**Mahamed-Maki Saine**  
Cybersecurity Student | Malware Analysis & Forensics Enthusiast
