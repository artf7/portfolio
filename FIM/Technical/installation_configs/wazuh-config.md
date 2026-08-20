Was taken path: Microsoft-Windows-Sysmon/Operational was placed in ossec.conf 
Final result: 
<localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

File integrity monitoring setting in ossec.conf: 
(frequency was changed to realtime for this specific path)
    <directories realtime="yes">C:\Users\artemfedorov\Documents\folder-to-be-monitored</directories>
