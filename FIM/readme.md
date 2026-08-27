# File Integrity Monitoring (FIM) — Project Summary

**Project:** Wazuh Security Monitoring — File Integrity Monitoring Module

## What is this project?

This project demonstrates the use of **File Integrity Monitoring (FIM)** to detect changes to files on a Windows endpoint.

FIM continuously monitors selected files and directories and generates security events when files are **created, modified, or deleted**. This provides visibility into changes that might otherwise happen without an obvious warning to the user or security team.

FIM works similar way as a sensor for important files: it records **what changed, which file was affected, and when the change occurred**.

## Why this matters to the business

Unexpected changes to important files can be an early indicator of a security incident, configuration problem, accidental change, or unauthorized activity.

A working FIM capability can help an organization:

* **Detect file tampering quickly.** Security teams can be alerted when monitored files are created, modified, or deleted.
* **Improve security visibility.** Instead of relying on users or administrators to report changes, the monitoring system automatically records them.
* **Support investigations and audits.** Events provide a historical record showing the affected file, type of change, and event timestamp.
* **Reduce the time to detect unexpected activity.** Near-real-time monitoring allows security teams to investigate suspicious changes shortly after they occur.
* **Protect security-relevant files.** FIM can be particularly useful when monitoring configuration files, application files, scripts, or other important system data.

## What was built and tested

Wazuh was configured to monitor a dedicated test directory on a Windows 11 endpoint in real time.

To demonstrate the detection capability, a single test file, `test.txt`, was taken through a complete file lifecycle:

1. **Created** inside the monitored directory.
2. **Modified** by changing its contents.
3. **Deleted** from the monitored directory.

Wazuh generated a separate security event for each operation.

The resulting alerts were:

| Event    | Wazuh Rule | Description                |
| -------- | ---------: | -------------------------- |
| Added    |        554 | File added to the system   |
| Modified |        550 | Integrity checksum changed |
| Deleted  |        553 | File deleted               |

The three events were recorded in the correct sequence within approximately **0.23 seconds**, demonstrating that the configured real-time monitoring was active during the test.

## Evidence: Wazuh FIM Alerts

The screenshot below shows the three events captured by the Wazuh dashboard.

![Wazuh FIM alerts showing the same file being added, modified, and deleted](Tech/screenshots/fim.png)

The dashboard shows:

* **Timestamp** — when the event was recorded
* **`syscheck.path`** — the file affected by the event
* **`syscheck.event`** — the type of change: `added`, `modified`, or `deleted`
* **`rule.description`** — Wazuh's description of the detected event
* **`rule.level`** — the severity level assigned by the Wazuh rule

All three events reference the same monitored file path, allowing the activity to be viewed as one observed file lifecycle: **added → modified → deleted**.

The underlying Wazuh alerts also contain file integrity information, including cryptographic hashes. These values provide additional evidence for correlating the observed file states across the three events.

## What the test demonstrates

The test demonstrates that the configured Wazuh FIM control can:

* Detect file creation in real time.
* Detect changes to an existing file.
* Detect file deletion.
* Record the affected file and event timestamp.
* Assign a Wazuh detection rule and severity to each event.
* Provide file integrity information that can be used to correlate observed file states.

This provides a practical example of how FIM can contribute to endpoint security monitoring.

## Important limitation

FIM establishes that a monitored file changed, but **FIM alone does not determine which user or process caused the change**.

For a real security investigation, FIM can therefore be combined with additional endpoint telemetry, such as Sysmon, to provide process and user context around the file activity.

For this project, all three file operations were intentional and performed as part of a controlled test.

## Bottom line

This project demonstrates a working and verifiable file integrity monitoring capability using Wazuh.

A controlled **create → modify → delete** sequence was successfully detected on a Windows endpoint, with each operation recorded as a separate security event.

The result demonstrates how FIM can give a security team timely visibility into changes to monitored files and provide useful evidence for further investigation when unexpected activity occurs.
