# Mimikatz Detection via Wazuh — Technical Writeup

**Component:** Wazuh custom detection rule (ID 100002), Sysmon, Windows Event Channel
**Endpoint:** Windows 11 VM running in Parallels
**Wazuh Agent:** `parallels`
**Wazuh Manager:** `LAPTOP-VO1HEOP5`
**Manager Platform:** Ubuntu 22.04 / WSL2
**Network:** LAN
**Test Date:** August 26, 2026
**MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory

---

## 1. Objective

This project demonstrates the detection of **Mimikatz v2.2.0 execution** on a Windows 11 endpoint using Wazuh and Sysmon.

The objective was to develop and validate a custom Wazuh rule that identifies Mimikatz execution by inspecting the executable's **PE (Portable Executable) metadata**, specifically the `OriginalFileName` field, rather than relying solely on the process filename.

The detection uses the following field and PCRE2 pattern:

```text
win.eventdata.originalFileName
(?i)mimikatz\.exe
```

When the condition is satisfied for a Sysmon process-creation event, Wazuh generates a **Level 15** alert using custom Rule ID `100002`.

The rule is mapped to **MITRE ATT&CK T1003.001 — OS Credential Dumping: LSASS Memory** to represent the credential-access threat associated with Mimikatz.

> **Scope:** The captured telemetry validates Mimikatz process execution and the resulting Wazuh detection. It does not by itself demonstrate that LSASS memory was accessed.

---

## 2. Architecture

The current lab consists of two separate Windows systems connected over a LAN.

The Windows 11 endpoint runs inside Parallels on one machine, while the Wazuh infrastructure runs in Ubuntu 22.04 under WSL2 on a separate Windows 11 laptop.

```text
Windows 11 Endpoint
Parallels VM
Agent: parallels
IP: 192.168.x.x
        │
        │ LAN
        ▼
Windows 11 Laptop
        │
        ▼
WSL2 / Ubuntu 22.04
Manager: LAPTOP-VO1HEOP5
        │
        ├── Wazuh Manager
        ├── Wazuh Indexer
        └── Wazuh Dashboard
```

### Event flow

```text
Mimikatz execution
        │
        ▼
Sysmon Event ID 1
(Process Creation)
        │
        ▼
Wazuh Agent
Windows Event Channel
        │
        │ LAN
        ▼
Wazuh Manager
        │
        ▼
Custom Rule 100002
        │
        ├── Level 15
        └── MITRE T1003.001
        │
        ▼
Wazuh Indexer
        │
        ▼
Wazuh Dashboard
```

The Wazuh alert identifies the endpoint agent as `parallels` and the Wazuh manager as `LAPTOP-VO1HEOP5`.


## 3. Detection Configuration

### 3.1 Custom Wazuh Rule — ID 100002

```xml
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
  <description>Mimikatz usage detected</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
</rule>
```

### Rule logic

| Configuration                        | Purpose                                                             |
| ------------------------------------ | ------------------------------------------------------------------- |
| `id="100002"`                        | Unique custom Wazuh rule ID                                         |
| `level="15"`                         | Assigns the highest Wazuh alert severity                            |
| `<if_group>sysmon_event1</if_group>` | Limits matching to Sysmon process-creation events                   |
| `win.eventdata.originalFileName`     | Inspects the PE `OriginalFileName` metadata                         |
| `type="pcre2"`                       | Uses the PCRE2 regular-expression engine                            |
| `(?i)mimikatz\.exe`                  | Case-insensitive match for `mimikatz.exe`                           |
| `T1003.001`                          | Associates the detection with the configured MITRE ATT&CK technique |

The rule does not rely solely on the executable's current filename. Instead, it evaluates the `OriginalFileName` field supplied by the Sysmon telemetry.

This provides an additional detection mechanism against simple executable renaming, although it should not be considered resistant to all forms of binary modification or evasion.


## 4. Sysmon Integration

The Wazuh agent collects Sysmon events through the Windows Event Channel:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

The relevant telemetry for this test is **Sysmon Event ID 1 — Process Create**.

The captured event contains:

```text
Image:
C:\Users\artemfedorov\Downloads\x64\mimikatz.exe

OriginalFileName:
mimikatz.exe

FileVersion:
2.2.0.0

ParentImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The Wazuh alert preserves the underlying Sysmon information.



## 5. Test Procedure

Mimikatz v2.2.0 x64 was executed directly from PowerShell on the Windows 11 endpoint to validate the detection rule.

| Parameter           | Value                                  |
| ------------------- | -------------------------------------- |
| Tool                | Mimikatz v2.2.0 x64                    |
| Execution method    | PowerShell                             |
| Command             | `.\mimikatz.exe`                       |
| Endpoint            | Windows 11 VM running in Parallels     |
| Wazuh agent         | `parallels`                            |
| Agent ID            | `001`                                  |
| Windows computer    | `ARTEMFEDOROF80D`                      |
| Location            | `C:\Users\artemfedorov\Downloads\x64\` |
| Parent process      | `powershell.exe`                       |
| Sysmon Event ID     | `1` — Process Create                   |
| Execution timestamp | `2026-08-26 17:33:27.995 UTC`          |

The captured Sysmon telemetry confirms the process creation event and records the executable, parent process, user, integrity level, version, and hashes.


## 6. Captured Process Evidence

The Sysmon event provides several useful indicators for investigation.

### PE metadata

```text
OriginalFileName: mimikatz.exe
FileVersion: 2.2.0.0
Description: mimikatz for Windows
Product: mimikatz
Company: gentilkiwi (Benjamin DELPY)
```

### Execution context

```text
Image:
C:\Users\artemfedorov\Downloads\x64\mimikatz.exe

CommandLine:
"C:\Users\artemfedorov\Downloads\x64\mimikatz.exe"

User:
ARTEMFEDOROF80D\artemfedorov

IntegrityLevel:
High
```

### Process lineage

```text
ParentImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

ParentProcessId:
4672

ProcessId:
1448
```

### File hashes

```text
SHA256:
61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1

SHA1:
E3B6EA8C46FA831CEC6F235A5CF48B38A4AE8D69

MD5:
29EFD64DD3C7FE1E2B022B7AD73A1BA5

IMPHASH:
55EE500BB4BDFC49F27A98AE456D8EDF
```

These fields are present in the captured Wazuh event payload.



## 7. Detection Results

The Mimikatz execution generated the expected Wazuh alert.

| Field                | Observed value            |
| -------------------- | ------------------------- |
| Wazuh Rule ID        | `100002`                  |
| Rule description     | `Mimikatz usage detected` |
| Alert level          | `15`                      |
| Agent                | `parallels`               |
| Agent ID             | `001`                     |
| MITRE technique      | `T1003.001`               |
| MITRE technique name | `LSASS Memory`            |
| MITRE tactic         | `Credential Access`       |
| Alert fired          | `1` time                  |

The Wazuh JSON confirms Rule `100002`, Level `15`, and the MITRE mapping to T1003.001.

### Detection latency

The Sysmon process-creation timestamp was:

```text
2026-08-26 17:33:27.995 UTC
```

The corresponding Wazuh alert timestamp was:

```text
2026-08-26 17:33:29.307 UTC
```

The observed difference is approximately:

**1.312 seconds**


## 8. Alert Evidence

### Screenshot 1 — Mimikatz Execution
![Execution](Screenshots\terminal_mimikatz_execution.jpg)

The first screenshot documents the actual Mimikatz execution from PowerShell on the Windows 11 Parallels endpoint.

**Evidence demonstrated:**

* Mimikatz v2.2.0 execution
* Windows endpoint context
* PowerShell execution
* Successful launch of the binary

### Screenshot 2 — Wazuh Alert
![Alert](Screenshots\wazuh_summery.png)
The second screenshot shows the resulting Wazuh Security Event.

**Evidence demonstrated:**

* Rule ID `100002`
* Rule description: `Mimikatz usage detected`
* Level `15`
* Agent `parallels`


### Complete JSON Evidence

The accompanying [Threat Description JSON file](Wazuh_Details\threat_description.json) contains the complete Wazuh alert payload and underlying Sysmon Event ID 1 data.

It provides evidence for:

* Process creation
* PE `OriginalFileName`
* Process image path
* Parent process
* Command line
* User
* Integrity level
* File version
* SHA256/SHA1/MD5/IMPHASH
* Wazuh rule execution
* MITRE mapping

The underlying event identifies Sysmon Event ID `1` and the `Microsoft-Windows-Sysmon/Operational` channel.

## 9. SOC Triage Assessment

From a SOC analyst perspective, the alert provides sufficient information for an initial assessment of the activity.

### Initial assessment

**Severity:** High

The alert identifies execution of a credential-access tool from a user's Downloads directory.

### Relevant observations

**1. Suspicious executable**

The PE metadata identifies the process as `mimikatz.exe`.

**2. User execution context**

The process was executed under:

```text
ARTEMFEDOROF80D\artemfedorov
```

**3. PowerShell parent process**

The parent process was:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This provides useful process-lineage context for further investigation.

**4. High integrity**

The process executed with:

```text
IntegrityLevel: High
```

**5. Binary identification**

The event contains multiple hashes, including SHA256, allowing the observed binary to be uniquely identified and correlated with additional threat-intelligence or endpoint data.

### Recommended SOC follow-up

In a production environment, an analyst could correlate this alert with additional endpoint telemetry to determine:

* Whether Mimikatz subsequently accessed LSASS
* Whether credential-dumping activity occurred
* Whether additional suspicious processes were created
* Whether PowerShell executed additional commands
* Whether credentials or authentication material were accessed
* Whether the same binary hash appeared on other endpoints

**Sysmon Event ID 10 — Process Access** would be particularly useful when investigating potential LSASS access.


## 10. Observations and Limitations

### Observations

* The custom Wazuh rule successfully detected the execution of Mimikatz v2.2.0.
* Detection was based on PE `OriginalFileName` metadata rather than only the executable's current filename.
* Sysmon provided detailed process telemetry that was preserved in the Wazuh alert.
* The captured event contains process-lineage and binary-identification information useful for SOC triage.
* The observed difference between the Sysmon event timestamp and Wazuh alert timestamp was approximately **1.3 seconds**.
* No false positives were observed during this specific test.
* The alert is mapped to **MITRE ATT&CK T1003.001 — OS Credential Dumping: LSASS Memory** because this technique is associated with Mimikatz's credential-dumping capabilities. The mapping represents the threat behavior associated with the detected tool; the captured **Sysmon Event ID 1** confirms process execution but does not by itself demonstrate LSASS memory access.

### Limitations

This was a **controlled lab validation**, not a production deployment.

The test validates the following detection chain:

```text
Mimikatz execution
        ↓
Sysmon Event ID 1
        ↓
Wazuh Agent
        ↓
LAN
        ↓
Wazuh Manager
        ↓
Custom Rule 100002
        ↓
Wazuh Level 15 alert
```

The captured event does not independently validate:

* LSASS memory access
* Credential extraction
* Detection against modified or recompiled Mimikatz binaries
* Detection against all renamed or obfuscated variants
* Production false-positive rates

Further validation using **Sysmon Event ID 10 — Process Access** could be performed if the objective is to demonstrate actual interaction with LSASS.


## 11. Conclusion

The Wazuh detection successfully identified the execution of Mimikatz v2.2.0 on the Windows 11 endpoint.

The project demonstrates an end-to-end detection workflow across two separate systems:

```text
Windows 11 Parallels VM
        ↓
Sysmon Event ID 1
        ↓
Wazuh Agent
        ↓
LAN
        ↓
Wazuh Manager
(WSL2 / Ubuntu 22.04)
        ↓
Custom Rule 100002
        ↓
Wazuh Alert
        ↓
Indexer
        ↓
Dashboard
```

The captured alert provides sufficient telemetry to establish **what executed, where it executed, which user executed it, which process launched it, and which binary hashes were observed**.

Using PE `OriginalFileName` rather than only the process filename provides an additional detection mechanism against simple executable renaming. However, further testing would be required to evaluate the rule against modified, obfuscated, or recompiled binaries.

The project therefore demonstrates a complete **endpoint telemetry → custom detection rule → SIEM alert → initial SOC triage** workflow in a controlled environment.



## 12. Lab Environment

### Endpoint

```text
Operating System: Windows 11
Hypervisor: Parallels
Wazuh Agent: parallels
Agent ID: 001
Windows Computer: ARTEMFEDOROF80D
Network: LAN
```

### Wazuh Infrastructure

```text
Host: Windows 11 Laptop
Virtualization: WSL2
Distribution: Ubuntu 22.04
Manager: LAPTOP-VO1HEOP5

Services:
├── Wazuh Manager
├── Wazuh Indexer
└── Wazuh Dashboard
```

The Wazuh alert identifies the agent as `parallels` and the manager as `LAPTOP-VO1HEOP5`.

---

## 13. Project Artifacts

The project contains the following evidence:

1. `fim.png` — Wazuh dashboard screenshot showing the three FIM alerts (file added, modified, and deleted) with timestamps, file paths, event types, and rule information.

2. `added.json` — Complete Wazuh alert payload for the file creation event, including syscheck metadata and full event details.

3. `modified.json` — Complete Wazuh alert payload for the file modification event, including integrity checksum information showing the file contents changed.

4. `deleted.json` — Complete Wazuh alert payload for the file deletion event, documenting the removal of the monitored file.

These four artifacts provide complete evidence of the file lifecycle monitoring capability: the screenshot shows the alerts as a security analyst would see them, while the three JSON files contain the underlying technical data captured for each event.

The JSON artifact contains the complete captured process-creation event, including PE metadata, process lineage, hashes, and the Wazuh rule result.
