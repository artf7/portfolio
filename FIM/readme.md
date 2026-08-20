# File Integrity Monitoring (FIM) — Project Summary

**Project:** Wazuh Security Monitoring — File Integrity Monitoring Module


## What is this project?

This project demonstrates a security control called **File Integrity Monitoring (FIM)**. In plain terms, FIM keeps a constant watch over a chosen folder on a computer and immediately flags any time a file inside it is **created, changed, or deleted** — even if the change happens quietly in the background, with no user popup or warning.

Think of it like a security camera pointed at a filing cabinet: it doesn't stop someone from opening a drawer, but it records exactly who touched what, and when, so nothing can happen unnoticed.

## Why this matters to the business

Unauthorized or unexpected changes to files are one of the most common early signs of a security problem — whether that's an employee mistake, a misconfigured system, malware tampering with data, or an attacker trying to cover their tracks. Without monitoring, these changes can go unnoticed for weeks or months.

A working FIM control supports the business in a few concrete ways:

- **Faster detection of tampering.** If a sensitive file is altered or deleted without authorization, the security team knows within seconds instead of finding out during an audit.
- **Audit and compliance readiness.** Many regulatory and industry frameworks (for example PCI DSS, HIPAA, and SOC 2) either require or strongly recommend file integrity monitoring on systems that handle sensitive data. Having a demonstrated, working FIM setup is direct evidence of that control being in place.
- **Accountability.** Every recorded event is tied to a timestamp, the affected file, and the type of change, creating a clear activity trail that can support internal investigations.
- **Reduced risk window.** Early detection shortens the time between "something bad happened" and "someone finds out," which limits potential damage.

## What was actually built and tested

For this project, a monitoring platform (Wazuh) was set up and configured to watch a specific test folder in real time. Three everyday file actions were performed to prove the system catches them all:

1. A new file was **added** to the monitored folder.
2. That file was **edited** (its contents were changed).
3. A file was **deleted** from the monitored folder.

Every one of these actions was captured automatically, with no manual reporting required, and appeared as a recorded event with a timestamp and description.

## Evidence: what the alerts look like

The screenshot below is taken directly from the monitoring dashboard. Each row is one detected event — reading it doesn't require technical knowledge:

- **timestamp** — when the action happened
- **syscheck.path** — which file was affected
- **syscheck.event** — what happened to it (added / modified / deleted)
- **rule.description** — a plain-English description of the event
- **rule.level** — how serious the system considers the event (higher number = more attention-worthy)

![Wazuh FIM alert dashboard showing add, modify, and delete events](Technical/screenshots/fim.png)

In this capture, the system correctly identified:

- A file being **added** to the folder
- That same file being **modified** shortly after
- A different file in the folder being **deleted**

Each event was logged automatically and in near real time, with no gaps and no manual intervention needed.

## Bottom line

This demonstrates a working, verifiable detection control: if someone creates, changes, or removes a file in a protected location, it does not go unnoticed. That's the kind of visibility auditors, compliance teams, and security leadership look for when evaluating whether an organization can actually detect tampering — not just claim to.