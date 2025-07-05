# doomsday_detector
Info: A Python based anti-cheat detection tool designed for Minecraft server administrators to identify traces of the Doomsday Client hack during screenshare sessions.

How it works?

Process Monitoring: Identifies suspicious running processes and Java instances with Doomsday-related arguments
File System Analysis: Searches directories for Doomsday files, JARs, and related folders
Minecraft Integration: Examines Minecraft directories including mods, versions, and log files
Registry Scanning: Checks Windows registry for Doomsday entries
JAR Analysis: Inspects JAR files for suspicious internal content
