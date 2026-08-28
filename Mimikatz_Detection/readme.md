# Mimikatz Detection Project — Non-Technical Overview

## 1. Project Overview

This project demonstrates how a security monitoring system can detect the use of **Mimikatz**, a tool commonly associated with credential theft and password-related attacks, on a Windows computer.

The goal was to build and validate a security detection that can identify when Mimikatz is executed on an endpoint and immediately generate a high-priority security alert for investigation.

The project was implemented as a controlled laboratory exercise using a Windows 11 endpoint and the Wazuh security monitoring platform.

## 2. The Problem

Attackers may use tools such as Mimikatz after gaining access to a Windows computer to attempt to obtain credentials or other authentication information.

Simply looking at the name of a running program is not always sufficient for detecting suspicious software, because an attacker can rename an executable to make it appear harmless.

The project therefore explored a more reliable way of identifying Mimikatz by examining information embedded within the executable itself, rather than relying only on its visible filename.

## 3. What Was Built

A custom detection was created within Wazuh to recognize Mimikatz execution.

The overall solution works as follows:

**Windows computer → Security monitoring → Detection → High-priority alert → SOC investigation**

When Mimikatz is launched:

1. The Windows computer records the program execution.
2. The security monitoring agent collects this information.
3. Wazuh analyzes the activity using the custom detection.
4. If the activity matches the detection criteria, Wazuh generates a high-priority alert.
5. The alert is made available to a security analyst for investigation.

This creates an end-to-end detection capability rather than simply demonstrating that Mimikatz can be executed.

## 4. Test Environment

The project was tested in a controlled lab environment.

The Windows 11 endpoint was running as a virtual machine, while the Wazuh monitoring infrastructure was hosted separately. The two systems communicated over the local network.

This setup allowed the project to simulate a simplified real-world security monitoring environment where activity on an endpoint is collected and analyzed centrally.

## 5. What the Detection Provides

When the detection is triggered, the security alert provides an analyst with useful information about the activity, including:

* Which computer was involved
* Which user launched the program
* What program was executed
* Which process launched it
* Where the program was located
* Information that can uniquely identify the executable
* The security classification associated with the activity

This information gives an analyst enough context to begin an initial investigation without having to manually reconstruct what happened on the endpoint.

## 6. Results

The detection successfully identified the execution of Mimikatz during testing.

The resulting Wazuh alert was classified as **high severity** and associated with the relevant MITRE ATT&CK credential-access technique.

The system detected the activity approximately **1.3 seconds** after the original Windows security event was recorded. No false positives were observed during this specific test.

The test therefore demonstrated that the monitoring pipeline was working from end to end:

**Mimikatz execution → Windows telemetry → Wazuh analysis → Security alert**

## 7. Value to a Security Operations Team

From a SOC perspective, the project demonstrates several important capabilities.

### 7.1.  Early Detection

The solution can identify the execution of a known credential-access tool shortly after it occurs.

### 7.2. Investigation Context

The alert contains information that helps an analyst understand **what happened, where it happened, and who was involved**.

### 7.3. Centralized Monitoring

Instead of relying on someone manually checking individual computers, endpoint activity is collected and analyzed centrally by Wazuh.

### 7.4 Improved Detection

The project demonstrates an approach that goes beyond simply looking at a program's visible filename, providing an additional way to recognize the tool.

### 7.5 MITRE ATT&CK Alignment

The detection is mapped to the MITRE ATT&CK framework, making it easier to understand the type of threat behavior being monitored and how it fits into a broader security program.

## 8. What This Project Proves

The project successfully proves that:

* Mimikatz execution can be detected on a Windows endpoint.
* Endpoint security information can be collected centrally.
* A custom security detection can automatically identify the activity.
* The detection can generate a high-priority alert.
* The alert contains useful information for initial SOC investigation.
* The complete process can occur within approximately 1.3 seconds in the test environment.

## 9. Important Limitation

This project demonstrates **detection of Mimikatz execution**, not proof that credentials were actually stolen.

The test confirmed that the Mimikatz program was launched, but the collected evidence does not independently demonstrate that Windows credential information was accessed or extracted.

In a production environment, additional monitoring would be required to determine whether the program subsequently interacted with sensitive Windows processes or performed credential-dumping activity.

## 10. Future Improvements

The project could be expanded to provide a more complete picture of an attack by adding additional detections and investigation capabilities.

Potential improvements include:

* Detecting attempts to access sensitive Windows processes
* Correlating multiple suspicious activities from the same endpoint
* Monitoring additional PowerShell activity
* Checking whether the same executable appears on other computers
* Expanding testing to modified or obfuscated versions of the tool
* Measuring false-positive rates in a larger environment

## 11. Conclusion

This project demonstrates a practical example of how endpoint security monitoring can be used to identify potentially malicious activity and turn it into an actionable security alert.

Rather than relying on manual investigation, the solution automatically collects endpoint activity, evaluates it against a custom detection, and presents the result to security personnel.

The final outcome is a complete **endpoint monitoring → threat detection → security alert → initial investigation** workflow.

Although the project was performed in a controlled laboratory environment, it provides a foundation that could be further developed into a broader endpoint detection capability for a production security operations environment.
