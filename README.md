# Advent of Cyber 2024

This repository documents my progress through TryHackMe's Advent of Cyber 2024. Each day involves a unique cybersecurity challenge, and I’ve recorded my process, tools used, and insights gained.

---

## Day 1: Investigating Malicious Websites

**Overview**  
Investigated a suspicious YouTube MP3 converter website. Discovered malicious `.lnk` files executing PowerShell scripts and traced the attacker using OSINT techniques.

**Key Steps**  
1. Identified a malicious Windows shortcut file (file somg.mp3).
2. Analyzed PowerShell commands for bypassing restrictions and downloading malicious scripts (exiftool somg.mp3).
3. Tracked the attacker on GitHub by exploiting OPSEC mistakes.


---

## Skills Demonstrated
- File analysis using `exiftool` and `file`.
- PowerShell command investigation.
- OSINT techniques for tracking threat actors.
