# Malware Signature Analysis (2024)

This project demonstrates the process of creating and testing a custom ClamAV signature for a suspicious file (`wzdu35.exe`).  
It includes calculating file properties, creating a signature file, scanning the file, and confirming that the signature does not generate false positives.

---

## Table of Contents

- [Overview](#overview)
- [File Size Check](#file-size-check)
- [SHA256 Hash Calculation](#sha256-hash-calculation)
- [Custom Signature Creation](#custom-signature-creation)
- [ClamAV Detection](#clamav-detection)
- [False Positive Test](#false-positive-test)
- [Findings and Conclusion](#findings-and-conclusion)

---

## Overview

This lab focused on generating a custom `.hdb` signature to detect a suspicious file.  
By using file size and SHA256 hash, we created a signature that uniquely matches `wzdu35.exe` and verified its accuracy with ClamAV.

---

## File Size Check

Command used:

```bash
stat -c%s wzdu35.exe
```

This step retrieves the exact file size, which is required for the `.hdb` signature format.

![File Size Screenshot](screenshots/stat_file_size_wzdu35.png)

---

## SHA256 Hash Calculation

Command used:

```bash
sha256sum wzdu35.exe
```

This generates the SHA256 hash that uniquely identifies the file.

![SHA256 Hash Screenshot](screenshots/sha256sum_wzdu35.png)

---

## Custom Signature Creation

The `.hdb` signature format requires the following syntax:

```
SHA256:FILESIZE:NAME
```

Example:

```bash
echo "73176a97801a58e4148e407a2b6336ad8791fd8fc381bffaa3cee753ec394d0a:21613504:WZDU35" > hemmelig_fil.hdb
```

![Signature Creation Screenshot](screenshots/create_signature_file.png)

---

## ClamAV Detection

Command used:

```bash
clamscan --database=./hemmelig_fil.hdb wzdu35.exe
```

Expected result: `FOUND`

![ClamAV Detection Screenshot](screenshots/clamscan_wzdu35_result.png)

---

## False Positive Test

To confirm that the signature does not match other files, a scan was performed on benign executables:

```bash
clamscan --database=./hemmelig_fil.hdb /path/to/other/files/*.exe
```

Expected result: `Infected files: 0`

![False Positive Test Screenshot](screenshots/clamscan_false_positive_test.png)

---

## Findings and Conclusion

- The custom signature successfully detected `wzdu35.exe`.
- No false positives were observed when scanning other files.
- Custom signatures are valuable for targeted detections when official databases do not yet flag the file.

**Conclusion:**  
This lab provided hands-on experience in signature creation and validation.  
It reinforced the importance of precise signatures that accurately detect malicious files without impacting legitimate software.

---

© 2024 Mahamed-Maki Saine
