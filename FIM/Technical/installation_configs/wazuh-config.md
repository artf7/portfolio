The path: `Microsoft-Windows-Sysmon/Operational` was placed in ossec.conf 

Final result: 
```xml
<localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
```
File integrity monitoring setting in `ossec.conf`: 
(update frequency was changed to `realtime` for this specific path)
```xml
    <directories realtime="yes">C:\Users\artemfedorov\Documents\folder-to-be-monitored</directories>
```