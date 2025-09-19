# Memory Analysis and YARA Detection (2024)

Dette prosjektet viser hvordan minneanalyse kan brukes for å identifisere en mistenkelig prosess, inspisere nettverksaktivitet og opprette en tilpasset YARA-regel for deteksjon.  
Prosjektet kombinerer bruk av **Volatility 3**, kommandoanalyse og praktiske funn fra minnedumpen.

---

## Table of Contents
- [Prosesslisteanalyse](#prosesslisteanalyse)
- [Nettverksanalyse](#nettverksanalyse)
- [YARA-regel og skanning](#yara-regel-og-skanning)
- [Konklusjon](#konklusjon)

---

## Prosesslisteanalyse

**Kommando brukt:**
```bash
python3 vol.py -f mem.raw windows.pslist
```

**Resultat:**  
Prosessen `wzdu35.exe` ble funnet med **PID 2312** og **PPID 288**.

![Process List Screenshot](screenshots/process_list_wzdu35.png)

---

## Nettverksanalyse

**Kommando brukt:**
```bash
python3 vol.py -f mem.raw windows.netscan
```

**Resultat:**  
Ingen åpne nettverksforbindelser ble funnet i minnedumpen på tidspunktet for analysen.

![Network Scan Screenshot](screenshots/network_scan_empty.png)

---

## YARA-regel og skanning

**Opprettelse av YARA-regel:**  
En tilpasset YARA-regel ble laget ved hjelp av `nano`:

```yara
rule analyse_wzdu35 {
    strings:
        $string1 = "wzdu35.exe"
    condition:
        $string1
}
```

![YARA File Creation Screenshot](screenshots/yara_rule_creation.png)

**Skanning av minne med YARA-regelen:**
```bash
python3 vol.py -f mem.raw windows.vadyarascan.VadYaraScan --yara-file analyse_wzdu35.yar
```

**Resultat:**  
Det ble funnet flere treff i prosessen med **PID 2312** og ett treff i prosessen med **PPID 288**.  
Dette bekrefter at prosessen inneholder strengen definert i YARA-regelen.

![YARA Scan Results Screenshot](screenshots/yara_scan_results.png)

---

## Konklusjon

Denne øvelsen ga verdifull praktisk erfaring i å kombinere minneanalyse og signaturbasert deteksjon.  
Ved å bruke prosessliste og nettverksskanning i Volatility ble det tydelig hvordan man kan identifisere mistenkelig aktivitet selv når det ikke finnes aktive forbindelser.  
Opprettelsen av en spesifikk YARA-regel viste hvordan det er mulig å finne nøyaktige treff i minnedata, og hvor viktig det er å lage regler som er presise for å unngå falske positive resultater.  
Denne prosessen styrket forståelsen av minneanalyse, YARA-regler og sammenhengen mellom prosessinformasjon og deteksjonsresultater.

---

© 2024 Mahamed-Maki Saine

