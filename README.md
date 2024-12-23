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


## Day 2: Log Analysis and Differentiating True vs False Positives

This project documents my approach to solving the Day 2 challenge of the Advent of Cyber 2024, where I analyzed logs in **Elastic SIEM**, detected a brute force attack, and resolved issues with outdated credentials.

---
 
### **Objective:**  
- Differentiate between true positives and false positives in alerts.  
- Investigate security events in Elastic SIEM to uncover potential threats.  

---

## **Project Details**  

### **Steps Taken:**  

1. **Accessing Elastic SIEM:**  
   - Visited [Elastic SIEM](https://10-10-254-213.p.thmlabs.com) and logged in.  
   - Username: `elastic`, Password: `elastic`.  

2. **Setting Timeframe for Analysis:**  
   - Based on the alert from the Mayor's Office, the suspicious activity occurred on **Dec 1st, 0900–0930**.  
   - Set the timeframe using the **absolute tab** and updated the view.  

3. **Initial Event Analysis:**  
   - Found **21 events** during the timeframe.  
   - Added key fields as columns:  
     - `host.hostname`: Identifies the affected host.  
     - `user.name`: The user who performed the activity.  
     - `event.category`: Ensures focus on relevant events.  
     - `process.command_line`: Shows the actual command executed.  
     - `event.outcome`: Confirms whether the activity succeeded.  

4. **Identified Suspicious Activity:**  
   - Detected an **encoded PowerShell command** executed on multiple machines.  
   - Observed successful authentication events immediately preceding the commands.  
   - Detected a generic admin account (`service_admin`) used for these actions.  

5. **Correlation of Events:**  
   - Tracked the source IP (`10.0.11.11`) associated with the PowerShell commands.  
   - Expanded the timeframe to analyze historical data (Nov 29–Dec 1 2024).  
   - Identified a spike in failed login attempts followed by successful login from a new IP (`10.0.255.1`).  

6. **Decoded PowerShell Command:**  
   - Used **CyberChef** to decode the Base64-encoded command:  
     - Recipe: `From Base64` configured to `UTF-16LE`.  
   - Revealed that outdated credentials in a Windows update script were updated after unauthorized access.  

7. **Root Cause Analysis:**  
   - Brute force attack successfully exploited outdated credentials.  
   - The attacker accessed machines, ran PowerShell commands, and updated the credentials.  

---

## **Key Findings**  
1. **Brute Force Attack:**  
   - Detected failed login attempts followed by successful authentication.  

2. **Outdated Credentials:**  
   - Automation script credentials were not updated, allowing exploitation.  

3. **Poor Admin Practices:**  
   - Use of generic admin accounts hindered accountability.  

---

## **Lessons Learned**  
- **Credential Hygiene:** Regularly update and monitor credentials in automation scripts.  
- **Admin Policies:** Assign unique, identifiable accounts to administrators.  
- **Log Monitoring:** Actively monitor and correlate events for timely detection of threats.  

---

## **Skills Demonstrated**  
- Log Analysis.  
- Event Correlation.  
- Base64 Decoding with CyberChef.  
- Threat Detection and Response.  
- Application of Cybersecurity Best Practices.  

---

## **Tools Used**  
- **Elastic SIEM**: For log investigation and filtering.  
- **CyberChef**: For decoding encoded commands.  

---

For a detailed explanation, check out the [Medium Article](https://medium.com/@cyberwitch/day-2-log-analysis-true-positive-vs-false-positive-advent-of-cyber-2024-df1f6ecf9f99).  


## Day 3: Frosty Pines Resort Investigation and Exploitation  

### Blue Team Investigation with ELK  
As a blue team analyst, I investigated a suspicious activity on the Frosty Pines website using Kibana. Here's what I uncovered:  
1. **Accessing Kibana**: Connected to the ELK stack via `http://10.10.110.47:5601`.  
2. **Filtering Logs**: Used the query `message: "shell.php"` and set the date/time range to October 3rd, 2024, between **11:30 and 12:00**.  
3. **Findings**: Discovered that a malicious `shell.php` file was uploaded to `/media/images/rooms/` by an attacker using IP `10.11.83.34`. Commands like `ls` and `pwd` were executed on the server.  

### Red Team Exploitation  
Switching to the offensive side, I recreated the attack:  
1. **Logged In**: Accessed the admin account on the Frosty Pines website.  
2. **Uploaded Malicious File**: Added a PHP reverse shell (`shell.php`) under the guise of an image.  
3. **Explored Server**: Navigated to the file location, executed commands, and found the `flag.txt` file.  
4. **Flag Retrieval**: Ran `cat flag.txt` to display the contents of the flag.  

### Key Recommendations:  
1. Enforce strict file validation to reject non-image file types during uploads.  
2. Remove execution permissions for files in upload directories.  
3. Regularly audit logs for suspicious activities.  

---

For a detailed explanation, check out the [Medium Article](https://medium.com/@cyberwitch/hi-there-in-this-post-im-excited-to-share-how-i-tackled-two-cybersecurity-challenges-involving-398294d476a2). 


# Day 4: Exploring Atomic Red Team & Sysmon Logs

Today’s task was all about exploring **Atomic Red Team** simulations and **Sysmon logs**. Here's a summary:

## **Steps Taken:**
1. Ran Atomic Red Team tests for:
   - **T1566.001 (Spearphishing)**
   - **T1059.003 (Windows Command Shell)**

2. Navigated through Sysmon logs to identify artefacts:
   - **phishing_attachment.txt**
   - **Wareville_Ransomware.txt**

3. Extracted flags and created detection rules based on findings.

---

## **Takeaways:**
- **Atomic Red Team** is great for testing and improving detection rules.
- **Sysmon Logs** help uncover artefacts generated by malicious actions.

For more details, check out my Medium post on Day 4's challenge [Medium Article](https://medium.com/@cyberwitch/day-4-atomic-red-team-advent-of-cyber-2024-f299d2c842dd).
