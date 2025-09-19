# Memory Analysis with Volatility & YARA (2024)

This project demonstrates memory forensics techniques using **Volatility 3** and **YARA**.  
The goal is to identify processes, check for network activity, and create a custom YARA rule to detect malicious code patterns.

---

## Table of Contents
[Process List Analysis](#process-list-analysis)
 
[Network Analysis](#network-analysis)
 
[YARA Rule Creation](#yara-rule-creation)
 
[YARA Scan Results](#yara-scan-results)
 
[Findings and Conclusion](#findings-and-conclusion)

---

## Process List Analysis

**Command used:**
```bash
python3 vol.py -f mem.raw windows.pslist
```

**Result:**  
The malicious process `wzdu35.exe` was identified with **PID 2312** and **PPID 288**.  
This confirms the process was running in memory at the time of capture.

![Process List Screenshot](screenshots/volatility_pslist_wzdu35.png)

---

## Network Analysis

**Command used:**
```bash
python3 vol.py -f mem.raw windows.netscan
```

**Result:**  
No active network connections were detected in the memory dump.  
This suggests the malware was not communicating externally during capture.

![Network Scan Screenshot](screenshots/volatility_netscan_empty.png)

---

## YARA Rule Creation

A custom YARA rule was created to match the presence of `wzdu35.exe` strings in memory.

**Rule content:**
```yara
rule analyse_wzdu35 {
    strings:
        $string1 = "wzdu35.exe"
    condition:
        $string1
}
```

![YARA Rule Content Screenshot](screenshots/yarafile_content.png)

---

## YARA Scan Results

**Command used:**
```bash
python3 vol.py -f mem.raw windows.vadyarascan.VadYaraScan --yara-file analyse_wzdu35.yar
```

**Result:**  
Multiple matches were found in memory, including the main process **PID 2312** and its parent process **PID 288**.  
This confirms that the YARA rule successfully detects the malicious process.

![YARA Scan Command Screenshot](screenshots/volatility_yarascan_command.png)

![YARA Scan Results Screenshot](screenshots/yarascan_results.png)

---

## Findings and Conclusion

This exercise reinforced the value of memory analysis in incident response.  
By using **pslist**, we confirmed the malicious process was running.  
With **netscan**, we verified no active network connections existed at the time of capture, reducing immediate risk.  
Finally, we created a **custom YARA rule** to reliably detect this process in memory, and validated that it produced no false positives.

This workflow demonstrates a practical approach to:
- Identifying suspicious processes  
- Checking for network activity  
- Writing precise detection rules  

Such techniques are essential for malware analysts and incident responders working to contain and investigate threats effectively.

---

