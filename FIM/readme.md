# Wazuh File Integrity Monitoring — Non-Technical Project Overview

## 1. Project Overview

This project demonstrates how an organization can monitor important files on Windows computers and detect when those files are **created, changed, or deleted**.

The solution uses Wazuh File Integrity Monitoring to continuously watch a designated location on a Windows 11 computer. When a change occurs, Wazuh generates a security event that can be reviewed by a security analyst.

The project was validated through a controlled test in which a single file was created, modified, and then deleted. Wazuh successfully detected all three actions.



## 2. Why File Integrity Monitoring Matters

Files can change for many reasons. Some changes are completely legitimate, such as software updates, administrator activity, or normal application operations.

However, unexpected file changes can also be an indicator of a security incident.

For example, an attacker who gains access to a computer might:

* Create a new file containing malicious code.
* Modify an existing configuration or application.
* Replace a legitimate file with a malicious version.
* Delete files to hide evidence or disrupt systems.

File Integrity Monitoring provides visibility into these changes so that security teams can identify activity that may require investigation.


## 3. What Was Built

The project configured Wazuh to monitor a specific directory on a Windows 11 endpoint in real time.

The monitoring process can be summarized simply as:

**Monitor → Detect → Record → Investigate**

When something happens to a monitored file, Wazuh records the event and provides information that can help an analyst understand what changed.

The project specifically validated three types of activity:

**File Created → File Modified → File Deleted**

Each action generated its own security alert.



## 4. How It Works — Simple Explanation

Think of the system as a **security camera for files**.

Wazuh keeps track of the expected state of files in a monitored location.

When a file appears, changes, or disappears, Wazuh notices the difference and records it.

For example:

### Step 1 — File Created

A new file called `test.txt` is placed in the monitored directory.

Wazuh detects that a new file has appeared and records its initial state.

### Step 2 — File Modified

The contents of `test.txt` are changed.

Wazuh detects that the file is no longer the same and records information about the change.

### Step 3 — File Deleted

The file is removed.

Wazuh detects that the previously monitored file is no longer present and records the deletion.

This creates a history of the file's observed lifecycle.


## 5. What Evidence Does the System Capture?

Wazuh records information that allows analysts to compare the state of a file before and after a change.

This includes information such as:

* File size
* Modification time
* File ownership
* File fingerprints
* The type of change that occurred
* When the change occurred
* The location of the file

One particularly useful piece of information is the file's **digital fingerprint**, commonly called a hash.

A hash can be thought of as a unique identifier for the contents of a file. If the contents change, the fingerprint normally changes as well.

In this project, the fingerprints from the different alerts matched in a consistent sequence, allowing the three events to be linked to the same `test.txt` file.


## 6. Project Results

The test successfully demonstrated all three required capabilities:

| Test                 | Result                    |
| -------------------- | ------------------------- |
| File creation        | Successfully detected     |
| File modification    | Successfully detected     |
| File deletion        | Successfully detected     |
| File state tracking  | Successfully demonstrated |
| Real-time monitoring | Successfully validated    |

The three events occurred within approximately **0.23 seconds**, demonstrating that the monitoring system was able to capture the controlled changes very quickly.

The validation results also confirmed that the file fingerprints formed a consistent chain between the creation, modification, and deletion events.


## 7. Security Operations Perspective

From a Security Operations Center (SOC) perspective, the main value of this project is **visibility**.

A FIM alert tells an analyst that something changed in a monitored location.

The analyst can then ask:

* Was this change expected?
* Was the file supposed to be created?
* Who or what might have caused the change?
* Was the file modified as part of legitimate activity?
* Was the file deleted intentionally?
* Does the change correspond with other suspicious activity?

This distinction is important because **a file change is not automatically a security incident**.

For example, a legitimate software update may modify many files. An administrator may intentionally delete a file. The alert provides the starting point for investigation rather than automatically declaring an attack.


## 8. What the Project Demonstrates

The project demonstrates that Wazuh can provide real-time visibility into the lifecycle of files within a monitored Windows directory.

More specifically, it demonstrates that the system can:

* Detect when a new file appears.
* Detect when an existing file changes.
* Detect when a file is removed.
* Record information about the file before and after changes.
* Link multiple events to the same file.
* Provide a timeline that can support security investigations.

The captured data was sufficient to reconstruct the complete observed lifecycle of `test.txt`.


## 9. Important Limitation

File Integrity Monitoring answers an important question:

> **"Did this file change?"**

However, by itself, it does not fully answer:

> **"Who changed it and why?"**

The project documentation specifically identifies this as a limitation.

FIM can show that a file changed, when it changed, and how its integrity information changed. Additional endpoint monitoring is required to determine which user or process caused the change.

This is why FIM is best viewed as **one layer of security monitoring**, rather than a complete investigation solution.


## 10. Future Improvements

The project provides a foundation that could be expanded by combining file monitoring with additional endpoint information.

For example, future development could correlate file changes with:

* The user who performed the action
* The application or process responsible
* Other Windows security events
* Network activity
* Other suspicious events occurring at the same time

This would allow analysts to move from simply knowing **that a file changed** to understanding **what caused the change and whether it was suspicious**.


## 11. Business and Security Value

The main value of this project is improved **endpoint visibility and investigation capability**.

In a real environment, monitoring important files can help security teams identify unexpected changes that could otherwise go unnoticed.

The capability can support:

**Early Detection**

Unexpected changes can be identified quickly.

**Investigation**

Security analysts have historical information about what happened to a monitored file.

**Accountability**

File activity can be correlated with additional security information to help determine what caused a change.

**Incident Response**

File-change information can provide useful evidence when investigating a potential security incident.

**Defense-in-Depth**

FIM provides an additional layer of visibility alongside other endpoint security controls.


## 12. Conclusion

This project successfully validated Wazuh File Integrity Monitoring on a Windows 11 endpoint.

A controlled test created, modified, and deleted the same file. Wazuh detected each action in real time and recorded enough information to connect the three events into a single file lifecycle.

The project demonstrates a simple but valuable security capability:

**A file changes → Wazuh detects the change → The event is recorded → A security analyst can investigate it**

While FIM alone cannot determine who or what caused a change, it provides an important layer of endpoint visibility. When combined with other security telemetry, it can help organizations detect suspicious activity and investigate potential security incidents more effectively.
