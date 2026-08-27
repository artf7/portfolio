# Wazuh File Integrity Monitoring — Real-Time Detection and File Lifecycle Analysis

Real-time detection of file creation, modification, and deletion on a Windows endpoint, with hash-based evidence linking the observed file states across its lifecycle.

* **Capability:** Wazuh File Integrity Monitoring (FIM / syscheck)
* **Wazuh:** 4.14
* **Endpoint:** Windows 11
* **Monitored path:** `...\folder-to-be-monitored`

All findings in this document are based on three raw Wazuh alerts captured during a controlled `add → modify → delete` test involving the same file, `test.txt`. The relevant alert payloads are included in the appendix.

---

## 1. Summary

This project configures and validates Wazuh File Integrity Monitoring on a Windows 11 endpoint using real-time monitoring.

A single test file, `test.txt`, was:

1. Created inside the monitored directory.
2. Modified by changing its contents.
3. Deleted from the monitored directory.

Wazuh generated a separate alert for each operation:

| Event    | Decoder                      | Rule ID | Level |
| -------- | ---------------------------- | ------: | ----: |
| Added    | `syscheck_new_entry`         |     554 |     5 |
| Modified | `syscheck_integrity_changed` |     550 |     7 |
| Deleted  | `syscheck_deleted`           |     553 |     7 |

The SHA256 values recorded in the alerts can be used to link the observed file states together. The SHA256 value from the creation event matches the `sha256_before` value in the modification event, while the `sha256_after` value from the modification event matches the final hash retained by the deletion event.

This provides strong hash-based evidence that the three alerts represent a continuous observed lifecycle of `test.txt`.

---

## 2. Objectives

The project had three primary objectives:

1. Configure Wazuh FIM (`syscheck`) to monitor a Windows directory in real time.
2. Validate detection of file creation, modification, and deletion.
3. Determine whether the resulting telemetry could be used to reconstruct the observed lifecycle of a file.

A secondary objective was to establish a foundation for future correlation between FIM events and Windows endpoint telemetry such as Sysmon.

---

## 3. Lab Architecture

The environment was self-hosted and used two separate physical machines.

| Component          | Platform                | Role                                 |
| ------------------ | ----------------------- | ------------------------------------ |
| Wazuh Manager 4.14 | Ubuntu 22.04 / WSL2     | Event processing and rule evaluation |
| Wazuh Indexer      | Ubuntu 22.04 / WSL2     | Alert storage                        |
| Wazuh Dashboard    | Ubuntu 22.04 / WSL2     | Security-event visualization         |
| Wazuh Agent 001    | Windows 11 in Parallels | Monitored endpoint                   |
| Syscheck           | Wazuh Agent             | File Integrity Monitoring            |

### Network topology

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

The Wazuh manager and monitored endpoint were located on separate physical machines connected through the local network. This validated the complete telemetry path from the Windows endpoint to the Wazuh manager and dashboard.

---

## 4. How Wazuh FIM Works

Wazuh File Integrity Monitoring is provided by the `syscheck` component.

Syscheck maintains information about files in configured directories, including attributes such as:

* File size
* Modification time
* Ownership information
* MD5 hash
* SHA1 hash
* SHA256 hash

The current state of a monitored file is compared with its previously observed state.

Based on the detected change, Wazuh can generate different FIM events:

* **Added** — a new file appears in a monitored location.
* **Modified** — one or more monitored attributes change.
* **Deleted** — a previously monitored file is no longer present.

### Real-time monitoring

The monitored directory was configured with `realtime="yes"`:

```xml
<directories realtime="yes">
  ...\folder-to-be-monitored
</directories>
```

Real-time monitoring allows syscheck to respond to filesystem changes as they occur rather than relying only on periodic scans.

The captured alerts confirm this configuration was active because each event contains:

```json
"mode": "realtime"
```

---

## 5. Configuration

The FIM configuration was added to the Wazuh agent's `ossec.conf`:

```xml
<syscheck>
  <directories realtime="yes">
    ...\folder-to-be-monitored
  </directories>
</syscheck>
```

### Configuration parameters

| Parameter              | Purpose                                                                                  |
| ---------------------- | ---------------------------------------------------------------------------------------- |
| `realtime="yes"`       | Enables real-time filesystem monitoring rather than scheduled scans                      |


The configuration was limited to a dedicated test directory to keep the test controlled and reduce unnecessary telemetry.

---

## 6. Test Procedure

A controlled lifecycle test was performed against a single file named `test.txt`.

| Step | Action                            | Expected event |
| ---: | --------------------------------- | -------------- |
|    1 | Create `test.txt`                 | `added`        |
|    2 | Modify the contents of `test.txt` | `modified`     |
|    3 | Delete `test.txt`                 | `deleted`      |

Using one file for all three operations allowed the resulting alerts to be compared and correlated using their file path, timestamps, size, and cryptographic hashes.

---

## 7. Detection Results

### 7.1 File Creation

**Rule:** 554
**Level:** 5
**Decoder:** `syscheck_new_entry`

Relevant telemetry:

```json
"event": "added",
"mode": "realtime",
"size_after": "32",
"sha256_after": "ca7666026c7ad7fcc52be8f5146c0972901eb1a0354a673519622a4aa2a13eac"
```

Wazuh detected the appearance of `test.txt` in the monitored directory.

The alert recorded the initial file size as 32 bytes and generated a SHA256 hash for the observed file state.

---

### 7.2 File Modification

**Rule:** 550
**Level:** 7
**Decoder:** `syscheck_integrity_changed`

Relevant telemetry:

```json
"event": "modified",
"mode": "realtime",
"changed_attributes": "size, md5, sha1, sha256",
"size_before": "32",
"size_after": "60",
"sha256_before": "ca7666026c7ad7fcc52be8f5146c0972901eb1a0354a673519622a4aa2a13eac",
"sha256_after": "cea79667bca3fe076d661a4d2c99e7c37d6acc52843d24a9fc1377f43b85313d"
```

The file changed from 32 bytes to 60 bytes.

Wazuh reported changes to:

* Size
* MD5
* SHA1
* SHA256

The most important relationship is:

```text
Added sha256_after
        =
Modified sha256_before
ca7666026c7ad7fcc52be8f5146c0972901eb1a0354a673519622a4aa2a13eac
```

This shows that the file state observed immediately before modification has the same SHA256 value as the state recorded when the file was added.

The event triggered rule 550 at level 7.

---

### 7.3 File Deletion

**Rule:** 553
**Level:** 7
**Decoder:** `syscheck_deleted`

Relevant telemetry:

```json
"event": "deleted",
"mode": "realtime",
"sha256_after": "cea79667bca3fe076d661a4d2c99e7c37d6acc52843d24a9fc1377f43b85313d"
```

Wazuh detected that `test.txt` was removed from the monitored directory.

The deletion event retained the last observed file attributes, including the final SHA256 value.

That value matches the SHA256 value recorded after modification:

```text
Modified sha256_after
        =
Deleted sha256_after
cea79667bca3fe076d661a4d2c99e7c37d6acc52843d24a9fc1377f43b85313d
```

This links the deletion event to the file state produced by the modification.

The event triggered rule 553 at level 7.

---

## 8. Hash-Based File Lifecycle Analysis

The SHA256 values from the three alerts form a consistent chain:

| Lifecycle stage | Field           | SHA256                                                             |
| --------------- | --------------- | ------------------------------------------------------------------ |
| Added           | `sha256_after`  | `ca7666026c7ad7fcc52be8f5146c0972901eb1a0354a673519622a4aa2a13eac` |
| Modified        | `sha256_before` | `ca7666026c7ad7fcc52be8f5146c0972901eb1a0354a673519622a4aa2a13eac` |
| Modified        | `sha256_after`  | `cea79667bca3fe076d661a4d2c99e7c37d6acc52843d24a9fc1377f43b85313d` |
| Deleted         | `sha256_after`  | `cea79667bca3fe076d661a4d2c99e7c37d6acc52843d24a9fc1377f43b85313d` |

The lifecycle can therefore be represented as:

```text
                  test.txt
                     │
                     ▼
              ┌──────────────┐
              │    ADDED     │
              │ 32 bytes     │
              │ SHA256 ca76  │
              └──────┬───────┘
                     │
                     │ same SHA256
                     ▼
              ┌──────────────┐
              │   MODIFIED   │
              │ 32 → 60 B    │
              │ ca76 → cea7  │
              └──────┬───────┘
                     │
                     │ same SHA256
                     ▼
              ┌──────────────┐
              │   DELETED    │
              │ Last state   │
              │ SHA256 cea7  │
              └──────────────┘
```

The file size provides an additional consistency check:

```text
Created:    32 bytes
Modified:   32 → 60 bytes
Deleted:    last observed size = 60 bytes
```

Together, the matching SHA256 values and consistent file-size progression provide strong evidence that the alerts represent the observed lifecycle of the same file.

This is useful during investigation because an analyst can use the FIM telemetry to determine how the observed file state changed over time.

---

## 9. Event Timeline

The Wazuh alerts contain timestamps that place the three events in sequence:

| Event    | File       | Wazuh event timestamp     |
| -------- | ---------- | ------------------------- |
| Added    | `test.txt` | `2026-08-26T13:34:44.778` |
| Modified | `test.txt` | `2026-08-26T13:34:44.948` |
| Deleted  | `test.txt` | `2026-08-26T13:34:45.009` |

The three alerts were generated within approximately 0.23 seconds of each other.

This is consistent with the controlled test being executed as a rapid create → modify → delete sequence.

These timestamps can also be used as a starting point when correlating FIM activity with other endpoint telemetry.

---

## 10. SOC Triage

A FIM alert does not automatically indicate malicious activity.

A file may be legitimately modified by:

* An administrator
* A user
* A software update
* An installation process
* A legitimate application

Therefore, the analyst must investigate the context surrounding the event.

### Example investigation workflow

```text
FIM Alert
    │
    ▼
Validate endpoint and file path
    │
    ▼
Determine whether the change was expected
    │
    ▼
Review file hash and changed attributes
    │
    ▼
Correlate with endpoint telemetry
    │
    ▼
Investigate process/user context
    │
    ▼
Review surrounding events
    │
    ▼
Determine severity and response
```

For this laboratory test, all file operations were intentional and authorized.

In a production environment, an unexpected modification followed by deletion could warrant further investigation, particularly when the monitored directory contains sensitive configuration files, executables, or other security-relevant data.

---

## 11. Coverage and Limitations

### What this project demonstrates

The configuration successfully detected file creation, modification, and deletion in real time. Each captured alert contained the file path, size, MD5, SHA1, and SHA256 hashes, modification time, changed attributes, real-time monitoring mode, and the associated Wazuh rule and severity.

### What FIM does not establish on its own

FIM records that a monitored file changed, when it changed, and which integrity attributes changed. It does not, by itself, establish:

* **Who or what made the change.** The alert identifies the file and its new state, not the process or user responsible. Correlating with Sysmon process telemetry (for example, Event ID 11 for file creation) is required to attribute the change.
* **Changes outside monitored paths.** Coverage is exactly the configured directories — nothing outside them is observed.
* **The specific content that changed.** FIM reports that content changed and the resulting hash, along with a size and attribute diff, but not the changed bytes themselves.

This is the core limitation of FIM as a standalone control: it is strong evidence that *something* changed, but it must be paired with process and user telemetry to establish *who* and *how*.

---

## 12. Validation Summary

| Test                    | Expected result       | Observed result             |
| ----------------------- | --------------------- | ----------------------------|
| Create `test.txt`       | `added` / Rule 554    | `added` / Rule 554          |
| Modify `test.txt`       | `modified` / Rule 550 | `modified` / Rule 550       |
| Delete `test.txt`       | `deleted` / Rule 553  | `deleted` / Rule 553        |
| Validate SHA256 chain   | Matching values       | Values matched across events|
| Validate real-time mode | `mode: realtime`      | Present in all three events |

---

## 13. Conclusion

The lab successfully validated Wazuh File Integrity Monitoring in real-time mode on a Windows 11 endpoint.

A controlled create → modify → delete sequence generated three distinct Wazuh alerts. The captured telemetry provided enough information to reconstruct the observed lifecycle of `test.txt`, including consistent file-size changes and matching SHA256 values between consecutive file states.

The project also demonstrates the role and limitation of FIM within a SOC. FIM can establish that a monitored file changed, when the event occurred, and what integrity attributes changed, but additional endpoint telemetry is required to investigate the process or user associated with the activity.

FIM can therefore serve as one layer of endpoint visibility, with Sysmon and other Windows telemetry providing additional context for investigation and incident response.

---

# Appendix — Captured Wazuh Alerts

The following alerts were retrieved from the Wazuh alert index:

`wazuh-alerts-4.x-2026.08.26`

The payloads below contain the fields used to perform the analysis in this document.

## A. Added

```json
{
  "agent": {
    "id": "001",
    "name": "parallels",
    "ip": "192.168.x.x"
  },
  "manager": {
    "name": "LAPTOP-VO1HEOP5"
  },
  "decoder": {
    "name": "syscheck_new_entry"
  },
  "location": "syscheck",
  "rule": {
    "id": "554",
    "level": 5,
    "description": "File added to the system.",
    "groups": [
      "ossec",
      "syscheck",
      "syscheck_entry_added",
      "syscheck_file"
    ]
  },
  "syscheck": {
    "path": "...\\folder-to-be-monitored\\test.txt",
    "event": "added",
    "mode": "realtime",
    "size_after": "32",
    "md5_after": "4d481386ae4e514203e0cd1f7a8098c6",
    "sha1_after": "96a3632b9ed8a49b2581daebf135a9238ebee5e4",
    "sha256_after": "ca7666026c7ad7fcc52be8f5146c0972901eb1a0354a673519622a4aa2a13eac",
    "uname_after": "Administrators",
    "mtime_after": "2026-08-26T10:34:44"
  },
  "full_log": "File '...\\folder-to-be-monitored\\test.txt' added\nMode: realtime",
  "timestamp": "2026-08-26T13:34:44.778"
}
```

## B. Modified

```json
{
  "agent": {
    "id": "001",
    "name": "parallels",
    "ip": "192.168.x.x"
  },
  "manager": {
    "name": "LAPTOP-VO1HEOP5"
  },
  "decoder": {
    "name": "syscheck_integrity_changed"
  },
  "location": "syscheck",
  "rule": {
    "id": "550",
    "level": 7,
    "description": "Integrity checksum changed.",
    "groups": [
      "ossec",
      "syscheck",
      "syscheck_entry_modified",
      "syscheck_file"
    ],
    "mitre": {
      "id": [
        "T1565.001"
      ],
      "technique": [
        "Stored Data Manipulation"
      ],
      "tactic": [
        "Impact"
      ]
    }
  },
  "syscheck": {
    "path": "...\\folder-to-be-monitored\\test.txt",
    "event": "modified",
    "mode": "realtime",
    "changed_attributes": "size, md5, sha1, sha256",
    "size_before": "32",
    "size_after": "60",
    "md5_before": "4d481386ae4e514203e0cd1f7a8098c6",
    "md5_after": "22b6c6112603cf431f8120ca0e96ffe5",
    "sha1_before": "96a3632b9ed8a49b2581daebf135a9238ebee5e4",
    "sha1_after": "185340b445d45ff7af7584894f5456fb87615a4e",
    "sha256_before": "ca7666026c7ad7fcc52be8f5146c0972901eb1a0354a673519622a4aa2a13eac",
    "sha256_after": "cea79667bca3fe076d661a4d2c99e7c37d6acc52843d24a9fc1377f43b85313d",
    "mtime_after": "2026-08-26T10:34:44"
  },
  "timestamp": "2026-08-26T13:34:44.948"
}
```

## C. Deleted

```json
{
  "agent": {
    "id": "001",
    "name": "parallels",
    "ip": "192.168.x.x"
  },
  "manager": {
    "name": "LAPTOP-VO1HEOP5"
  },
  "decoder": {
    "name": "syscheck_deleted"
  },
  "location": "syscheck",
  "rule": {
    "id": "553",
    "level": 7,
    "description": "File deleted.",
    "groups": [
      "ossec",
      "syscheck",
      "syscheck_entry_deleted",
      "syscheck_file"
    ],
    "mitre": {
      "id": [
        "T1070.004",
        "T1485"
      ],
      "technique": [
        "File Deletion",
        "Data Destruction"
      ],
      "tactic": [
        "Defense Evasion",
        "Impact"
      ]
    }
  },
  "syscheck": {
    "path": "...\\folder-to-be-monitored\\test.txt",
    "event": "deleted",
    "mode": "realtime",
    "size_after": "60",
    "md5_after": "22b6c6112603cf431f8120ca0e96ffe5",
    "sha1_after": "185340b445d45ff7af7584894f5456fb87615a4e",
    "sha256_after": "cea79667bca3fe076d661a4d2c99e7c37d6acc52843d24a9fc1377f43b85313d",
    "uname_after": "Administrators",
    "mtime_after": "2026-08-26T10:34:44"
  },
  "full_log": "File '...\\folder-to-be-monitored\\test.txt' deleted\nMode: realtime",
  "timestamp": "2026-08-26T13:34:45.009"
}
```

**Test conclusion:** All three FIM operations were successfully detected in real time. The matching SHA256 values and consistent file-size progression provide strong evidence linking the three alerts into a single observed file lifecycle.