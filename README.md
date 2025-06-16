<h1 align="center">
    <img src="https://readme-typing-svg.herokuapp.com/?font=Righteous&size=35&color=4257f5&center=true&vCenter=true&width=500&height=70&duration=2000&lines=E/Email+Security+Simulation+Project;" />
</h1>

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

## ✅ SCENARIO 1: Phishing Email Detection
<details>
<summary><strong> Click here to expand </summary></strong>

### 📖 Real-World Context:
A finance employee receives a phishing email mimicking their payroll system. It urges them to click a malicious link.

### 📧 Sample Email:
From: hr-support@payroll-verify-alert.com  
To: finance_dept@company.com  
Subject: Urgent: Action Required to Release Salary  
Body: Click [http://payroll-verify-alert.com/login](#) to update your info.

### ❌ Red Flags:
- External spoofed domain
- Urgency (salary delay)
- Fake link

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
```kql
PhishingLog_CL
| where AlertType == "ALERT"
| where Subject has_any("Urgent", "Action", "Suspension")
| extend DomainCheck = iif(SenderFromAddress endswith "@company.com", "Trusted", "Suspicious")
| project TimeGenerated=Timestamp, Recipient, SenderFromAddress, Subject, DomainCheck, ThreatType
```

### 🎯 MITRE ATT&CK Mapping:
- T1566.001: Spearphishing via Service
- T1585.001: Email Spoofing

### 🔐 Prevention:
- Enable Safe Links (Defender)
- Anti-phishing policies (VIP impersonation)
- SPF, DKIM, DMARC setup

</details>

---


## ✅ SCENARIO 2: Data Loss Prevention (DLP) on Emails
<details><strong><summary>Click here to expand </strong></summary>

### 📖 Context:
An employee sends SSNs and credit cards to a third-party vendor.

### 🧪 Log Sample:
```
Timestamp | Sender | Recipient | AttachmentName | DataTypeDetected | PolicyViolated
2025-06-16 09:12:45 | maria.lopez@company.com | external_vendor@partners.com | client_records.xlsx | SSN, Credit Card Number | External Email with PII
```

### 🧠 KQL Detection:
```kql
DLPLog_CL
| where DataTypeDetected has_any ("SSN", "Credit Card")
| where Recipient !endswith "@company.com"
| project Timestamp, Sender, Recipient, DataTypeDetected, PolicyViolated
```

### 🎯 MITRE Mapping:
- T1041: Exfiltration Over C2
- T1537: Cloud Transfer

### 🛡️ Prevention:
- Purview DLP rules
- Auto-labeling in Office apps
- Train employees

</details>

---

## ✅ SCENARIO 3: Malware in Email Attachments
<details><strong><summary>Click here to expand </strong></summary>

### 📖 Context:
An email with `.docm` attachment carries a macro-based downloader.

### 🧪 Log Sample:
```
Timestamp | Sender | Recipient | AttachmentName | FileType | ThreatDetected | ActionTaken
2025-06-16 10:10:12 | billing@invoiceportal.net | danielle.watson@company.com | Invoice.docm | macro-enabled | TrojanDownloader | Quarantined
```

### 🧠 KQL Detection:
```kql
MalwareEmailLog_CL
| where ThreatDetected != "Clean"
| where FileType in ("macro-enabled", ".exe", ".scr")
| project Timestamp, Sender, Recipient, AttachmentName, ThreatDetected
```

### 🎯 MITRE Mapping:
- T1204.002: User Execution via Malicious File

### 🛡️ Prevention:
- Safe Attachments (Defender)
- Block .exe/.js/.docm
- Disable macros

</details>

---

## ✅ SCENARIO 4: Email Firewall (ETRs)

<details><strong><summary>Click here to expand </strong></summary>

### 📖 Context:
Block domains like `.ru`, spam with .exe attachments.

### 🧪 Log Sample:
```
Timestamp | Sender | Recipient | Subject | Attachment | RuleMatched | ActionTaken
2025-06-17 10:23:11 | promotions@freelottery.ru | emma@company.com | You’ve Won | gift.exe | Block Executables | Quarantined
```

### 🧠 KQL Detection:
```kql
FirewallEmailLog_CL
| where ActionTaken in ("Rejected", "Quarantined")
| project Timestamp, Sender, Subject, Attachment, RuleMatched
```

### 🛡️ Prevention:
- Exchange Transport Rules (ETRs)
- Block by filetype/sender/domain
- Regex keyword matches

</details>

---

## ✅ SCENARIO 5: Email Spoofing and SPF Failures
<details><summary>Click to expand</summary>

### 📖 Context:
A spoofed exec email fails SPF and is flagged.

### 🧪 Log Sample:
```
Timestamp | Sender | Recipient | Subject | SPFResult | DMARCResult | DKIMResult
2025-06-18 09:45:23 | ceo@company-hr.com | tom@company.com | Important: Download Payroll | Fail | None | None
```

### 🧠 KQL Detection:
```kql
EmailHeaderLog_CL
| where SPFResult == "Fail"
| where DMARCResult == "None" or DKIMResult == "None"
| project Timestamp, Sender, Recipient, Subject, SPFResult, DKIMResult, DMARCResult
```
---

### 📊 Dummy Detection Table

| Timestamp           | AlertType | Subject                             | Recipient               | SenderFromAddress                   | ThreatType     |
|---------------------|-----------|--------------------------------------|--------------------------|--------------------------------------|----------------|
| 2025-06-15 11:14:33 | ALERT     | Urgent: Action Required to Release Salary | finance_dept@company.com | hr-support@payroll-verify-alert.com | URL Phishing   |
| 2025-06-15 11:16:12 | ALERT     | Your Action Needed Today             | kate.james@company.com   | helpdesk@secure-hr.net              | URL Phishing   |

---

### 🛡️ Prevention:
- Add SPF DNS record with valid senders
- Enable DKIM key signing
- SPF, DKIM, DMARC setup policy to quarantine/reject
- Anti-phishing policies

</details>

---

### 🧠 MITRE ATT&CK Mapping

- T1566.001: Spearphishing via Service
- T1585.001: Email Spoofing

---

### 🧯 Incident Response

- Tier 1 tags phishing alert
- Tier 2 isolates user device
- Sandbox test of link
- Transport rule updated
- IOC reported

</details>

---

### ✅ Summary

This simulation set helps SOC analysts understand and test:
- Threat detection via logs
- Real SOC playbook steps
- MITRE coverage and incident response actions













<h1 align="center">
    <img src="https://readme-typing-svg.herokuapp.com/?font=Righteous&size=35&color=4257f5&center=true&vCenter=true&width=500&height=70&duration=2000&lines=E/Email+Security+Simulation+Project;" />
</h1>

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

## ✅ SCENARIO 1: Phishing Email Detection
<details>
<summary><strong> Click here to expand </summary></strong>

### 📖 Real-World Context:
A finance employee at a mid-sized company receives an email that appears to be from the payroll department. The email urges the recipient to click a link to avoid salary delays.
This is a classic phishing attempt aiming to steal login credentials or deliver malware.

### 📧 Sample Email:
From: hr-support@payroll-verify-alert.com
To: finance_dept@company.com
Subject: Urgent: Action Required to Release Salary
Body:

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

| Timestamp           | AlertType | Subject                             | Recipient               | SenderFromAddress                   | ThreatType     |
|---------------------|-----------|--------------------------------------|--------------------------|--------------------------------------|----------------|
| 2025-06-15 11:14:33 | ALERT     | Urgent: Action Required to Release Salary | finance_dept@company.com | hr-support@payroll-verify-alert.com | URL Phishing   |



### 🎯 MITRE ATT&CK Mapping
- [T1566.001 - Spearphishing via Service](https://attack.mitre.org/techniques/T1566/001/)
- [T1585.001 - Spoofing Email Accounts](https://attack.mitre.org/techniques/T1585/001/)

### 🧠 Alerting Process
Analyst receives alert inside Sentinel → Investigates message → Confirms spoofed sender

### 🔐 Prevention:
- Enable Safe Links (Defender)
- Anti-phishing policies (VIP impersonation)
- SPF, DKIM, DMARC setup
- Safe Links
- Anti-Phishing Policy
- SPF, DKIM, DMARC

</details>

---


## ✅ SCENARIO 2: Data Loss Prevention (DLP) on Emails
<details>
<summary><strong> Click here to expand </summary></strong>

### 📖 Real-World Context:
An employee from the finance department attempts to send a spreadsheet containing Social Security Numbers (SSNs) and credit card details to an external vendor via email. This violates company policies on sharing Personally Identifiable Information (PII) outside the organization.

### 📧 Sample Email:
Sender: maria.lopez@company.com
Recipient: external_vendor@partners.com
Attachment: client_records.xlsx
Data Types: SSN, Credit Card Number
Violation: External email with PII

### ❌ Red Flags:
- 
- 
### 🧪 Analyst Action:
1. Create file `dlp_alert.log`

```
Timestamp | Sender | Recipient | AttachmentName | DataTypeDetected | PolicyViolated  
2025-06-16 09:12:45 | maria.lopez@company.com | external_vendor@partners.com | client_records.xlsx | SSN, Credit Card Number | External Email with PII 
```


```
Timestamp | Sender | Recipient | AttachmentName | FileType | ThreatDetected | ActionTaken  
2025-06-16 10:10:12 | billing@invoiceportal.net | danielle.watson@company.com | Invoice.docm | macro-enabled | TrojanDownloader | Quarantined  
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
| project Timestamp, Sender, Recipient, DataTypeDetected, PolicyViolated
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


</details>

---

## ✅ SCENARIO 3: Malware in Email Attachments
<details> <summary><strong>🦠 Click here to expand</strong></summary>

### 📖 Real-World Context:
A user in the finance department receives an email from an unknown invoicing domain. The message includes a .docm (macro-enabled) attachment, which contains a malicious macro that attempts to download and execute a trojan from a remote server.

### 📧 Sample Email:
From: billing@invoiceportal.net
To: danielle.watson@company.com
Subject: New Invoice for Review
Attachment: Invoice.docm

When the user opens this file and enables macros, a hidden PowerShell script executes and contacts an external command-and-control (C2) server to download a trojan payload.

### ❌ Red Flags:
- 
- 
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
| project Timestamp, Sender, Recipient, AttachmentName, ThreatDetected
```


### 🧪 Dummy Logs (MalwareEmailLog_CL)

| Timestamp           | Sender | Recipient                             | AttachmentName               | FileType                   | ThreatDetected    | ActionTaken |
|---------------------|-----------|--------------------------------------|--------------------------|--------------------------------------|----------------|-------------|
| 2025-06-15 11:14:33 | billing@invoiceportal.net    | danielle.watson@company.com | Invoice.docm | SSN | URL Phishing   |Credit Card  | TrojanDownloader | Quarantined  |


### 🎯 MITRE ATT&CK Mapping
- T1204.002 – User Execution: Malicious File
- T1059 – Command and Scripting Interpreter (via PowerShell)

### 🧠 What Analysts See After Alert
Alert shows in Microsoft Sentinel DLP dashboard

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
✅ Safe Attachments (Microsoft Defender for Office 365)
✅ Block risky extensions (.docm, .exe, .js)
✅ Disable macros by default for all Office files
✅ Enable Zero-Hour Auto Purge (ZAP)
✅ Enable attachment sandboxing in email security policy


</details>

---

## ✅ SCENARIO 4: Email Firewall using Exchange Transport Rules (ETRs)
<details> <summary><strong>🛑 Click here to expand</strong></summary>

### 📖 Real-World Context:
A marketing employee receives an email from a Russian domain promoting a fake lottery win. The message contains an executable .exe file as an attachment. This could be a malware dropper intended to compromise the endpoint.

These types of spam or malware-laced emails are often blocked at the perimeter using Exchange Transport Rules (ETRs), acting like a firewall for your email flow.

### 📧 Sample Email:
From: promotions@freelottery.ru
To: emma@company.com
Subject: 🎉 You’ve Won a New Phone
Attachment: gift.exe

### ❌ Red Flags:
- Sender domain ends in .ru (known TLD abuse)
- Executable file attachment .exe
- Subject line includes clickbait or rewards
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
| project Timestamp, Sender, Subject, Attachment, RuleMatched
```


### 🧪 Dummy Logs (MalwareEmailLog_CL)

| Timestamp           | Sender | Recipient                             | Attachment               | RuleMatched                   | ThreatDetected    | ActionTaken |
|---------------------|-----------|--------------------------------------|--------------------------|--------------------------------------|----------------|-------------|
| 2025-06-15 11:14:33 | promotions@freelottery.ru    | emma@company.com | You’ve Won	gift.exe |Block Executables  |  TrojanDownloader | Quarantined  |


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
✅ Use Exchange Transport Rules (ETRs) to block messages with .exe, .js, or foreign domains
✅ Block known malicious domains or country TLDs like .ru, .cn, .tk
✅ Use Regex keyword filters for lottery, win, free, reward, etc.
✅ Enable Defender for Office 365 to inspect attachments and apply Safe Attachments
✅ Regularly audit and test ETR policies


</details>

---

## ✅ SCENARIO 5: Email Spoofing and SPF Failures
<details> <summary><strong>🚨 Click here to expand</strong></summary>

### 📖 Real-World Context:
An attacker sends a spoofed email appearing to come from the CEO of the company. The email urges the recipient to download a file related to payroll. On inspection, the email fails SPF (Sender Policy Framework) validation and has no DKIM (DomainKeys Identified Mail) or DMARC (Domain-based Message Authentication, Reporting & Conformance) signatures — clear signs of spoofing.

### 📧 Sample Email:
From: ceo@company-hr.com
To: tom@company.com
Subject: ⚠️ Important: Download Payroll Document
Body: Please download the attached payroll update immediately.

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
✅ SPF (Sender Policy Framework): Add DNS TXT record to specify allowed IPs/domains to send email on your behalf
✅ DKIM (DomainKeys Identified Mail): Digitally signs emails with your domain
✅ DMARC (Domain-based Message Authentication): Specifies action for failed SPF/DKIM (none, quarantine, reject)
✅ Anti-phishing policies targeting VIP name spoofing and lookalike domains
✅ Block emails failing SPF from sending to internal distribution lists


### 🧯 Incident Response Steps
- Tier 1 confirms alert from Sentinel
- Tier 2 isolates recipient’s device and blocks sender
- Header analysis is done to extract attack infrastructure
- SOC creates transport rule to quarantine similar emails
- IOC (Indicator of Compromise) added to threat intelligence feed
- Awareness email sent to finance or executive group

</details>

---
