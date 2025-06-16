# $${{\color{Orange}\normalsize{\textsf{Email Security Simulation Project}}}}$$



## 🔐 Project Title: Email Security Simulation Using Microsoft Sentinel

### 🔓 Project Objective
This simulation showcases how common email threats are detected and mitigated using Microsoft Defender for Office 365, Exchange mail rules and Microsoft Sentinel. The goal is to demonstrate end-to-end visibility for analysts of all skill levels.

---

This document provides real-world, beginner-friendly simulations to understand how SOC analysts detect and respond to various email-based attacks using:
- Microsoft Sentinel (SIEM)
- Microsoft Defender for Office 365
- Exchange Transport Rules (ETRs)
- Microsoft Purview DLP

---

### ✅ SCENARIO 1: Phishing Email Detection
<details>
<summary><strong> Click here to expand </summary></strong>

### 📖 Real-World Context:
A finance employee at a mid-sized company receives an email that appears to be from the payroll department. The email urges the recipient to click a link to avoid salary delays.
This is a classic phishing attempt aiming to steal login credentials or deliver malware.

<div align="center">
<img src =images/PhishingEmailDetected.png width="300" height="200>
</div>
 </br>

### 📧 Sample Email:
- From: hr-support@payroll-verify-alert.com
- To: finance_dept@company.com
- Subject: Urgent: Action Required to Release Salary
- Body:

Your payroll verification is pending. Click the link to avoid salary delay:
http://payroll-verify-alert.com/login

### ❌ Red Flags:
- External spoofed domain
- Urgency (salary delay)
- Fake link
- Urgent language: “Action Required”
- External spoofed domain
- Misleading hyperlink
- Impersonation of internal dept.

### 🧪 Analyst Action:
1. Create file `phishing_alert.log`
```
Timestamp | AlertType | Subject | Recipient | SenderFromAddress | ThreatType
2025-06-15 11:14:33 | ALERT | Urgent: Action Required to Release Salary | finance_dept@company.com | hr-support@payroll-verify-alert.com | URL Phishing
```

2. Upload to VM: `C:\SecurityLogs\phishing_alert.log`  
3. Create DCR using Sentinel > Data Connectors > Custom Logs  
4. Log Table: `PhishingLog_CL`

### 🧠 KQL Detection:
```kusto
PhishingLog_CL
| where AlertType == "ALERT"
| where Subject has_any("Urgent", "Action", "Suspension")
| extend DomainCheck = iif(SenderFromAddress endswith "@company.com", "Trusted", "Suspicious")
| project TimeGenerated=Timestamp, Recipient, SenderFromAddress, Subject, DomainCheck, ThreatType
```


### 🧪 Dummy Logs (PhishingLog_CL)

| Timestamp           | AlertType | Subject                             | Recipient               | SenderFromAddress        |   DomainCheck |    | ThreatType 
|---------------------|-----------|--------------------------------------|--------------------------|--------------------------------------|----------------|-----------|
| 2025-06-15 11:14:33 | ALERT     | Urgent: Action Required to Release Salary | finance_dept@company.com | hr-support@payroll-verify-alert.com | @payroll-verify-alert.com  | URL Phishing   |



### 🎯 MITRE ATT&CK Mapping
- [T1566.001 - Spearphishing via Service](https://attack.mitre.org/techniques/T1566/001/)
- [T1585.001 - Spoofing Email Accounts](https://attack.mitre.org/techniques/T1585/001/)

### 🧠 Alerting Process
- Microsoft Sentinel Incident Notification is triggered via custom analytic rule or connector (e.g., Defender for Office 365 or custom log ingestion).
- Alert appears in the Incidents pane within Sentinel, tagged under "Phishing" or "Email Spoof".
- Tier 1 SOC Analyst investigates sender domain, message headers, and hyperlinks.
- Analyst checks against internal allowlists and recent user reports.
- Teams or Email alert (if configured) notifies analyst or security team in real-time.

### 🔐 Prevention Techniques:
- Safe Links (Microsoft Defender)
Scans and rewrites URLs in emails; blocks known malicious links before click.

- Anti-Phishing Policies
Detects impersonation of VIPs or internal domains using behavioral analytics.

- SPF (Sender Policy Framework)
Verifies if sender IPs are authorized for the domain.

- DKIM (DomainKeys Identified Mail)
Adds a digital signature to ensure the message hasn’t been altered.

- DMARC (Domain-based Message Authentication, Reporting & Conformance)
Uses SPF and DKIM results to instruct receiving servers to reject/quarantine spoofed emails.


### 🧯 Incident Response Steps
- Alert Detected in Microsoft Sentinel from Defender for Office 365, showing spoofed HR email with a suspicious link.
- Tier 1 Analyst investigates sender, confirms phishing, and checks if others received similar emails using KQL.
- Tier 2 Analyst quarantines the email, tests the malicious link in a sandbox, and blocks the sender domain and IOCs.
- Containment includes purging the email from all inboxes and applying transport rules to stop similar future attacks.
- Recovery & Awareness involves notifying users, resetting passwords (if clicked), and updating phishing training examples.


</details>

---


### ✅ SCENARIO 2: Data Loss Prevention (DLP) on Emails
<details>
<summary><strong> Click here to expand </summary></strong>

### 📖 Real-World Context:
An employee from the finance department attempts to send a spreadsheet containing Social Security Numbers (SSNs) and credit card details to an external vendor via email. This violates company policies on sharing Personally Identifiable Information (PII) outside the organization.

<div align="center">
<img src =images/SensitiveDataExfiltraton.png width="500">
</div>
 </br>
 
### 📧 Sample Email:
- Sender: maria.lopez@company.com
- Recipient: external_vendor@partners.com
- Attachment: client_records.xlsx
- Data Types: SSN, Credit Card Number
- Violation: External email with PII

### ❌ Red Flags:
- Employee sending sensitive data (SSNs, credit card numbers) to an external domain
- Email attachments named like “client_records.xlsx” or “confidential_data.csv”
- No encryption or data masking applied before sending
- Violates company DLP policy on regulated PII (Personally Identifiable Information)
- Frequent large file transfers to unknown or unapproved recipients


### 🧪 Analyst Action:
1. Create file `dlp_alert.log`

```
Timestamp | Sender | Recipient | AttachmentName | DataTypeDetected | PolicyViolated  
2025-06-16 09:12:45 | maria.lopez@company.com | external_vendor@partners.com | client_records.xlsx | SSN, Credit Card Number | External Email with PII 
```

2. Upload to VM: `C:\SecurityLogs\dlp_alert.log`
3. Create DCR using Sentinel > Data Connectors > Custom Logs  
4. Log Table: `DLPLog_CL`
5. Path: C:\SecurityLogs\dlp_alert.log


### 🧠 KQL Detection(DLPLog_CL):
```kusto
DLPLog_CL
| where DataTypeDetected has_any ("SSN", "Credit Card")  // Look for PII keywords
| where Recipient !endswith "@company.com"               // Only flag external sending
| project Timestamp, Sender, Recipient, AttachmentName, DataTypeDetected, PolicyViolated
```


### 🧪 Dummy Logs (DLPLog_CL)

| Timestamp           | Sender | Recipient                             | AttachmentName               | DataTypeDetected                   | PolicyViolated     |
|---------------------|-----------|--------------------------------------|--------------------------|--------------------------------------|----------------|
| 2025-06-15 11:14:33 | maria.lopez@company.com     | external_vendor@partners.com | client_records.xlsx | SSN | URL Phishing   |Credit Card


### 🎯 MITRE ATT&CK Mapping
- T1041 – Exfiltration Over Command and Control Channel
- T1537 – Transfer Data to Cloud Account

### 🧠 What Analysts See After Alert
Alert shows in Microsoft Sentinel DLP dashboard

### Analyst checks:
- Sender and recipient domain
- Content type (SSN, card info)
- Any existing override or justification from the user
- Coordinates with compliance/GRC teams if it's a confirmed policy violation

### 🧠 Alerting Process
- Sentinel Incident Notification
- Microsoft Purview DLP policy alerts
- Email/Teams notifications if enabled

### 🔐 Prevention:
- ✅ Microsoft Purview DLP Rules: Block or warn when PII is detected
- ✅ Auto-labeling in Office Apps: Applies sensitivity labels to content
- ✅ Train Employees: Conduct security awareness to reduce accidental data sharing
- ✅ Quarantine or Policy Tips: Inform user in Outlook before sending- Enable Safe Links (Defender)


### 🧯 Incident Response Steps
- Alert Triggered by Microsoft Purview DLP rule in Sentinel for PII (SSN/Credit Card) shared with external vendor.
- Tier 1 Analyst reviews the email logs and confirms that sensitive fields were detected in the attachment.
- Tier 2 Analyst contacts sender to confirm intent and checks if similar data was shared in the past (data exfil pattern).
- Containment involves applying encryption policy, temporarily disabling outbound email for the user, and alerting compliance.
- Recovery & Remediation includes retraining the user, updating DLP rules for stricter enforcement, and documenting the case for audits.

</details>

---

### ✅ SCENARIO 3: Malware in Email Attachments
<details> <summary><strong>🦠 Click here to expand</strong></summary>

### 📖 Real-World Context:
A user in the finance department receives an email from an unknown invoicing domain. The message includes a .docm (macro-enabled) attachment, which contains a malicious macro that attempts to download and execute a trojan from a remote server.

<div align="center">
<img src =images/MalwareEmail.png width="500">
</div>
 </br>

### 📧 Sample Email:
- From: billing@invoiceportal.net
- To: danielle.watson@company.com
- Subject: New Invoice for Review
- Attachment: Invoice.docm

When the user opens this file and enables macros, a hidden PowerShell script executes and contacts an external command-and-control (C2) server to download a trojan payload.

### ❌ Red Flags:
- Email contains attachments with risky extensions like .docm, .exe, .js, or .scr
- Sender’s domain is not recognized or impersonates a known vendor
- Attachment names like Invoice.docm, Payment.exe designed to trigger curiosity or urgency
- File behavior triggers antivirus or Defender for Office 365
- Unexpected attachments from external senders with generic subject lines


### 🧪 Analyst Action:
1. Create file `malware_email.log`

```
Timestamp | Sender | Recipient | AttachmentName | FileType | ThreatDetected | ActionTaken  
2025-06-16 10:10:12 | billing@invoiceportal.net | danielle.watson@company.com | Invoice.docm | macro-enabled | TrojanDownloader | Quarantined  
```
2. Upload to VM: `C:\SecurityLogs\malware_email.log`
3. Create DCR using Sentinel > Data Connectors > Custom Logs  
4. Log Table: `MalwareEmailLog_CL`
5. Path: C:\SecurityLogs\malware_email.log


### 🧠 KQL Detection(MalwareEmailLog_CL):
```kusto
MalwareEmailLog_CL
| where ThreatDetected != "Clean"                                  // Only show threats
| where FileType in ("macro-enabled", ".exe", ".scr")              // Filter suspicious file types
| project Timestamp, Sender, Recipient, AttachmentName, FileType, ThreatDetected, ActionTaken
```


### 🧪 Dummy Logs (MalwareEmailLog_CL)

| Timestamp           | Sender | Recipient                             | AttachmentName               | FileType                   | ThreatDetected    | ActionTaken |
|---------------------|-----------|--------------------------------------|--------------------------|--------------------------------------|----------------|-------------|
| 2025-06-15 11:14:33 | billing@invoiceportal.net    | danielle.watson@company.com | Invoice.docm | SSN | URL Phishing   |Credit Card  | TrojanDownloader | Quarantined  |


### 🎯 MITRE ATT&CK Mapping
- T1204.002 – User Execution: Malicious File
- T1059 – Command and Scripting Interpreter (via PowerShell)

### 🧠 Analyst Workflow After Alert
- Detection Triggered in Sentinel
- Analyst views alert details in Incidents blade
- Confirms attachment type, sender domain reputation, quarantine status
- Cross-checks user activity logs for execution behavior

If confirmed, triggers incident response workflow

### 🛑 Notification Types:

- Microsoft Defender Alert Email
- Sentinel Incident Notification
- SIEM dashboard (Visual alert with severity level)

### 🔐 Prevention Techniques
- ✅ Safe Attachments (Microsoft Defender for Office 365)
- ✅ Block risky extensions (.docm, .exe, .js)
- ✅ Disable macros by default for all Office files
- ✅ Enable Zero-Hour Auto Purge (ZAP)
- ✅ Enable attachment sandboxing in email security policy


### 🧯 Incident Response Steps
- Alert Triggered by Defender for Office 365 detecting malware in the email attachment and quarantining it.
- Tier 1 Analyst checks the attachment’s hash, sender IP, and whether the recipient opened or forwarded the file.
- Tier 2 Analyst isolates the endpoint if the attachment was clicked, then runs a malware scan and collects memory dumps.
- Containment includes blocking sender’s domain, updating anti-malware policies, and revoking access tokens if lateral movement is detected.
- Recovery involves submitting malware sample to sandbox, patching endpoint if needed, and adding the hash to threat blocklists.


</details>

---

### ✅ SCENARIO 4: Email Firewall using Exchange Transport Rules (ETRs)
<details> <summary><strong>🛑 Click here to expand</strong></summary>

### 📖 Real-World Context:
A marketing employee receives an email from a Russian domain promoting a fake lottery win. The message contains an executable .exe file as an attachment. This could be a malware dropper intended to compromise the endpoint.

These types of spam or malware-laced emails are often blocked at the perimeter using Exchange Transport Rules (ETRs), acting like a firewall for your email flow.

<div align="center">
<img src =images/MaliciousFilesDetected.png width="500">
</div>
 </br>

### 📧 Sample Email:
- From: promotions@freelottery.ru
- To: emma@company.com
- Subject: 🎉 You’ve Won a New Phone
- Attachment: gift.exe

### ❌ Red Flags:
-Emails from domains with risky TLDs like .ru, .cn, .top
- Attachments with .exe, .scr, .bat—commonly associated with malware
- Subject lines like “You’ve Won” or “Claim Now” indicating spam or fraud
- Recipients receive the same message across departments (mass campaign)
- Email headers missing SPF/DKIM authentication
- Sender domain ends in .ru (known TLD abuse)
- Impersonal and generic language

### 🧪 Analyst Action:
1. Create file `email_firewall_block.log`

```
Timestamp | Sender | Recipient | Subject | Attachment | RuleMatched | ActionTaken  
2025-06-17 10:23:11 | promotions@freelottery.ru | emma@company.com | You’ve Won | gift.exe | Block Executables | Quarantined  
```
2. Upload to VM: `C:\SecurityLogs\email_firewall_block.log`
3. Create DCR using Sentinel > Data Connectors > Custom Logs  
4. Log Table: `FirewallEmailLog_CL`
5. Path: C:\SecurityLogs\email_firewall_block.log


### 🧠 KQL Detection(FirewallEmailLog_CL):
```kusto
FirewallEmailLog_CL
| where ActionTaken in ("Rejected", "Quarantined")           // Look for blocked or quarantined messages
| project Timestamp, Sender, Recipient, Subject, Attachment, RuleMatched, ThreatDetected, ActionTaken
```


### 🧪 Dummy Logs (MalwareEmailLog_CL)

| Timestamp           | Sender | Recipient                             | Subject   | Attachment               | RuleMatched                   | ThreatDetected    | ActionTaken |
|---------------------|-----------|----------------|----------------------|--------------------------|--------------------------------------|----------------|-------------|
| 2025-06-15 11:14:33 | promotions@freelottery.ru    | emma@company.com | You’ve Won a New Phone	| gift.exe |Block Executables  |  TrojanDownloader | Quarantined  |


### 🎯 MITRE ATT&CK Mapping
- T1566.002 – Phishing: Link
- T1204.001 – User Execution: Malicious Link or Attachment


### 🧠 Analyst Workflow After Alert
- Analyst sees alert triggered via SIEM or Email notification from Defender
- Opens alert → Reviews sender and file type → Confirms block/quarantine
- May cross-reference with known IOCs or sender domain reputation
- Checks if similar messages were delivered to other inboxes
- Escalates if part of campaign or triggers user awareness follow-up

### 🛑 Notification Types:

- Microsoft Defender Alert Email
- Sentinel Incident Notification
- SIEM dashboard (Visual alert with severity level)

### 🔐 Prevention Techniques
- ✅ Use Exchange Transport Rules (ETRs) to block messages with .exe, .js, or foreign domains
- ✅ Block known malicious domains or country TLDs like .ru, .cn, .tk
- ✅ Use Regex keyword filters for lottery, win, free, reward, etc.
- ✅ Enable Defender for Office 365 to inspect attachments and apply Safe Attachments
- ✅ Regularly audit and test ETR policies


### 🧯 Incident Response Steps
- Alert Detected when ETR rule matches suspicious filetype or sender domain—email gets quarantined or rejected.
- Tier 1 Analyst reviews quarantine logs, identifies scope (how many users received the email).
- Tier 2 Analyst traces sender domain reputation and blocklist status, updates rules to extend protection if new variants are seen.
- Containment Actions include blacklisting the domain, tightening ETRs with regex or more precise keywords, and preventing delivery of similar patterns.
- Recovery and Awareness: Add domain to transport blocklist, alert affected users not to whitelist manually, and update playbooks for future TLD-based threats.

</details>

---

### ✅ SCENARIO 5: Email Spoofing and SPF Failures
<details> <summary><strong>🚨 Click here to expand</strong></summary>

### 📖 Real-World Context:
An attacker sends a spoofed email appearing to come from the CEO of the company. The email urges the recipient to download a file related to payroll. On inspection, the email fails SPF (Sender Policy Framework) validation and has no DKIM (DomainKeys Identified Mail) or DMARC (Domain-based Message Authentication, Reporting & Conformance) signatures — clear signs of spoofing.

<div align="center">
<img src =images/SppofedDomain.png width="500">
</div>
 </br>
 
### 📧 Sample Email:
- From: ceo@company-hr.com
- To: tom@company.com
- Subject: ⚠️ Important: Download Payroll Document
- Body: Please download the attached payroll update immediately.

### ❌ Red Flags:
- Suspicious external domain (looks similar to official)
- SPF failed validation
- No DKIM or DMARC present
- Uses urgency tactic
- Targeting employee from finance

### 🧪 Analyst Action:
1. Create file `spoofed_email_spf_fail.log`

```
Timestamp | Sender | Recipient | Subject | SPFResult | DMARCResult | DKIMResult  
2025-06-18 09:45:23 | ceo@company-hr.com | tom@company.com | Important: Download Payroll | Fail | None | None  
```
2. Upload to VM: `C:\SecurityLogs\spoofed_email_spf_fail.log`
3. Create DCR using Sentinel > Data Connectors > Custom Logs  
4. Log Table: `EmailHeaderLog_CL`
5. Path: C:\SecurityLogs\spoofed_email_spf_fail.log


### 🧠 KQL Detection(EmailHeaderLog_CL):
```kusto
EmailHeaderLog_CL
| where SPFResult == "Fail"                             // SPF failure indicates sender not authorized
| where DMARCResult == "None" or DKIMResult == "None"   // No domain validation or email signature
| project Timestamp, Sender, Recipient, Subject, SPFResult, DKIMResult, DMARCResult
```


### 🧪 Dummy Logs (MalwareEmailLog_CL)

| Timestamp           | Sender | Recipient                             | Subject              | SPFResult                 | DMARCResult   | DKIMResult |
|---------------------|-----------|--------------------------------------|--------------------------|--------------------------------------|----------------|-------------|
| 2025-06-15 11:14:33 | ceo@company-hr.com    | tom@company.com |Important: Download Payrol | Fail |  None | None  |


### 🎯 MITRE ATT&CK Mapping
- T1566.001 – Spearphishing via Service
- T1585.001 – Spoofing Email Accounts

### 🧠 Analyst Workflow After Alert
- Alert appears in Microsoft Sentinel or Defender dashboard
- Analyst investigates header details and confirms external spoof
- Analysts may check similar sender addresses used recently
- Incident ticket is created for potential spoofing attack

### 🛑 Notification Types:

- Microsoft Defender Alert Email
- Sentinel Incident Notification
- SIEM dashboard (Visual alert with severity level)

### 🔐 Prevention Techniques
- ✅ SPF (Sender Policy Framework): Add DNS TXT record to specify allowed IPs/domains to send email on your behalf
- ✅ DKIM (DomainKeys Identified Mail): Digitally signs emails with your domain
- ✅ DMARC (Domain-based Message Authentication): Specifies action for failed SPF/DKIM (none, quarantine, reject)
- ✅ Anti-phishing policies targeting VIP name spoofing and lookalike domains
- ✅ Block emails failing SPF from sending to internal distribution lists


### 🧯 Incident Response Steps
- Tier 1 confirms alert from Sentinel
- Tier 2 isolates recipient’s device and blocks sender
- Header analysis is done to extract attack infrastructure
- SOC creates transport rule to quarantine similar emails
- IOC (Indicator of Compromise) added to threat intelligence feed
- Awareness email sent to finance or executive group

</details>

---

<details>
<summary><strong>📜 Project License (MIT)</strong></summary>

MIT License  
Copyright (c) 2025 Bharathkasyap  

Permission is hereby granted...  
<!-- (same as above, keep rest inside the tag) -->

</details>

