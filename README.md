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

✅ SCENARIO 1: Phishing Email Detection
<details> <summary><strong>🔍 Click here to expand</strong></summary>
📖 Real-World Context
A finance employee at a mid-sized company receives an email that appears to be from the payroll department. The email urges the recipient to click a link to avoid salary delays.
This is a classic phishing attempt aiming to steal login credentials or deliver malware.

📧 Sample Email (Spoofed)
From: hr-support@payroll-verify-alert.com
To: finance_dept@company.com
Subject: Urgent: Action Required to Release Salary
Body:

Your payroll verification is pending. Click the link to avoid salary delay:
http://payroll-verify-alert.com/login

🚨 Red Flags in the Email
Sender domain mismatch (not from company domain)

Urgent tone to cause panic

Hyperlink leads to unknown domain

Spoofing of internal HR department

🧪 Analyst Simulation Steps
Create Dummy Log File:
Save the following to a text file named phishing_alert.log:

sql
Copy
Edit
Timestamp | AlertType | Subject | Recipient | SenderFromAddress | ThreatType  
2025-06-15 11:14:33 | ALERT | Urgent: Action Required to Release Salary | finance_dept@company.com | hr-support@payroll-verify-alert.com | URL Phishing  
Upload to VM:
Place the file at C:\SecurityLogs\phishing_alert.log on your Azure VM.

Configure Data Collection Rule (DCR):

Go to Microsoft Sentinel > Data Connectors > Custom Logs

Path: C:\SecurityLogs\phishing_alert.log

Table name: PhishingLog_CL

Log Ingestion Complete

📊 Dummy Detection Table (PhishingLog_CL)
Timestamp	AlertType	Subject	Recipient	SenderFromAddress	ThreatType
2025-06-15 11:14:33	ALERT	Urgent: Action Required to Release Salary	finance_dept@company.com	hr-support@payroll-verify-alert.com	URL Phishing

📌 Detection Logic (KQL Query)
kusto
Copy
Edit
PhishingLog_CL
| where AlertType == "ALERT"  // Show only alerts
| where Subject has_any("Urgent", "Action", "Suspension")  // Trigger keywords
| extend DomainCheck = iif(SenderFromAddress endswith "@company.com", "Trusted", "Suspicious")
| project TimeGenerated=Timestamp, Recipient, SenderFromAddress, Subject, DomainCheck, ThreatType
🧠 What Analysts See After Alert
Alert shown in Sentinel's Incident Queue

Analyst clicks the alert to view sender, subject, and message details

Analyst checks whether this email was clicked or ignored

Correlates with sign-in logs or malware alerts

🛎️ Alerts may also trigger:

Email notifications (if configured)

Microsoft Teams SOC channel messages

SIEM dashboards

🎯 MITRE ATT&CK Techniques
T1566.001 – Spearphishing via Service

T1585.001 – Spoofing Email Accounts

🛡️ Prevention Measures
✅ Enable Safe Links: Microsoft Defender scans all URLs on click

✅ Anti-Phishing Policies: Detect impersonation, especially of VIPs

✅ SPF (Sender Policy Framework): Blocks spoofed domains

✅ DKIM (DomainKeys Identified Mail): Ensures message hasn’t been modified

✅ DMARC: Quarantines or rejects emails failing SPF/DKIM

</details>


✅ SCENARIO 2: Data Loss Prevention (DLP) on Emails
<details> <summary><strong>🧾 Click here to expand</strong></summary>
📖 Real-World Context
An employee from the finance department attempts to send a spreadsheet containing Social Security Numbers (SSNs) and credit card details to an external vendor via email. This violates company policies on sharing Personally Identifiable Information (PII) outside the organization.

📧 Incident Description
Sender: maria.lopez@company.com
Recipient: external_vendor@partners.com
Attachment: client_records.xlsx
Data Types: SSN, Credit Card Number
Violation: External email with PII

🧪 Analyst Simulation Steps
Create Log File named dlp_alert.log:

sql
Copy
Edit
Timestamp | Sender | Recipient | AttachmentName | DataTypeDetected | PolicyViolated  
2025-06-16 09:12:45 | maria.lopez@company.com | external_vendor@partners.com | client_records.xlsx | SSN, Credit Card Number | External Email with PII  
Upload to VM:
Place it under: C:\SecurityLogs\dlp_alert.log

Configure Data Collection Rule (DCR):

Go to Microsoft Sentinel > Data Connectors > Custom Logs

Path: C:\SecurityLogs\dlp_alert.log

Table name: DLPLog_CL

📊 Dummy Log Table (DLPLog_CL)
Timestamp	Sender	Recipient	AttachmentName	DataTypeDetected	PolicyViolated
2025-06-16 09:12:45	maria.lopez@company.com	external_vendor@partners.com	client_records.xlsx	SSN, Credit Card Number	External Email with PII

📌 Detection Logic (KQL Query)
kusto
Copy
Edit
DLPLog_CL
| where DataTypeDetected has_any ("SSN", "Credit Card")  // Look for PII keywords
| where Recipient !endswith "@company.com"               // Only flag external sending
| project Timestamp, Sender, Recipient, DataTypeDetected, PolicyViolated
🧠 What Analysts See After Alert
Alert shows in Microsoft Sentinel DLP dashboard

Analyst checks:

Sender and recipient domain

Content type (SSN, card info)

Any existing override or justification from the user

Coordinates with compliance/GRC teams if it's a confirmed policy violation

🔔 Analysts may receive:

Sentinel Incident Notification

Microsoft Purview DLP policy alerts

Email/Teams notifications if enabled

🎯 MITRE ATT&CK Techniques
T1041 – Exfiltration Over Command and Control Channel

T1537 – Transfer Data to Cloud Account

🛡️ Prevention and Controls
✅ Microsoft Purview DLP Rules: Block or warn when PII is detected

✅ Auto-labeling in Office Apps: Applies sensitivity labels to content

✅ Train Employees: Conduct security awareness to reduce accidental data sharing

✅ Quarantine or Policy Tips: Inform user in Outlook before sending

</details>


✅ SCENARIO 3: Malware in Email Attachments
<details> <summary><strong>🦠 Click here to expand</strong></summary>
📖 Real-World Context
A user in the finance department receives an email from an unknown invoicing domain. The message includes a .docm (macro-enabled) attachment, which contains a malicious macro that attempts to download and execute a trojan from a remote server.

📧 Incident Email Sample
From: billing@invoiceportal.net
To: danielle.watson@company.com
Subject: New Invoice for Review
Attachment: Invoice.docm

When the user opens this file and enables macros, a hidden PowerShell script executes and contacts an external command-and-control (C2) server to download a trojan payload.

🧪 Log Simulation
Step 1: Create a log file malware_email.log

sql
Copy
Edit
Timestamp | Sender | Recipient | AttachmentName | FileType | ThreatDetected | ActionTaken  
2025-06-16 10:10:12 | billing@invoiceportal.net | danielle.watson@company.com | Invoice.docm | macro-enabled | TrojanDownloader | Quarantined  
Step 2: Place the log in VM path:
C:\SecurityLogs\malware_email.log

Step 3: Create DCR:

Go to Microsoft Sentinel → Data Connectors → Custom Logs

Path: C:\SecurityLogs\malware_email.log

Table: MalwareEmailLog_CL

📊 Dummy Log Table (MalwareEmailLog_CL)
Timestamp	Sender	Recipient	AttachmentName	FileType	ThreatDetected	ActionTaken
2025-06-16 10:10:12	billing@invoiceportal.net	danielle.watson@company.com	Invoice.docm	macro-enabled	TrojanDownloader	Quarantined

📌 KQL Detection Logic
kql
Copy
Edit
MalwareEmailLog_CL
| where ThreatDetected != "Clean"                                  // Only show threats
| where FileType in ("macro-enabled", ".exe", ".scr")              // Filter suspicious file types
| project Timestamp, Sender, Recipient, AttachmentName, ThreatDetected
🧠 Analyst Workflow After Alert
Detection Triggered in Sentinel

Analyst views alert details in Incidents blade

Confirms attachment type, sender domain reputation, quarantine status

Cross-checks user activity logs for execution behavior

If confirmed, triggers incident response workflow

🛑 Notification Types:

Microsoft Defender Alert Email

Sentinel Incident Notification

SIEM dashboard (Visual alert with severity level)

🎯 MITRE ATT&CK Mapping
T1204.002 – User Execution: Malicious File

T1059 – Command and Scripting Interpreter (via PowerShell)

🔐 Prevention Techniques
✅ Safe Attachments (Microsoft Defender for Office 365)

✅ Block risky extensions (.docm, .exe, .js)

✅ Disable macros by default for all Office files

✅ Enable Zero-Hour Auto Purge (ZAP)

✅ Enable attachment sandboxing in email security policy

</details>


✅ SCENARIO 4: Email Firewall using Exchange Transport Rules (ETRs)
<details> <summary><strong>🛑 Click here to expand</strong></summary>
📖 Real-World Context
A marketing employee receives an email from a Russian domain promoting a fake lottery win. The message contains an executable .exe file as an attachment. This could be a malware dropper intended to compromise the endpoint.

These types of spam or malware-laced emails are often blocked at the perimeter using Exchange Transport Rules (ETRs), acting like a firewall for your email flow.

📧 Email Sample
From: promotions@freelottery.ru
To: emma@company.com
Subject: 🎉 You’ve Won a New Phone
Attachment: gift.exe

❌ Red Flags
Sender domain ends in .ru (known TLD abuse)

Executable file attachment .exe

Subject line includes clickbait or rewards

Impersonal and generic language

🧪 Simulated Log File
Create file email_firewall_block.log

nginx
Copy
Edit
Timestamp | Sender | Recipient | Subject | Attachment | RuleMatched | ActionTaken  
2025-06-17 10:23:11 | promotions@freelottery.ru | emma@company.com | You’ve Won | gift.exe | Block Executables | Quarantined  
Upload to VM under: C:\SecurityLogs\email_firewall_block.log
Create a custom DCR in Sentinel → Data Connectors → Custom Logs
Table Name: FirewallEmailLog_CL

📊 Dummy Log Table (FirewallEmailLog_CL)
Timestamp	Sender	Recipient	Subject	Attachment	RuleMatched	ActionTaken
2025-06-17 10:23:11	promotions@freelottery.ru	emma@company.com	You’ve Won	gift.exe	Block Executables	Quarantined

📌 KQL Detection Logic
kql
Copy
Edit
FirewallEmailLog_CL
| where ActionTaken in ("Rejected", "Quarantined")           // Look for blocked or quarantined messages
| project Timestamp, Sender, Subject, Attachment, RuleMatched
🧠 What Happens After the Alert?
Analyst sees alert triggered via SIEM or Email notification from Defender

Opens alert → Reviews sender and file type → Confirms block/quarantine

May cross-reference with known IOCs or sender domain reputation

Checks if similar messages were delivered to other inboxes

Escalates if part of campaign or triggers user awareness follow-up

🧠 MITRE ATT&CK Mapping
T1566.002 – Phishing: Link

T1204.001 – User Execution: Malicious Link or Attachment

🔐 Prevention Techniques
✅ Use Exchange Transport Rules (ETRs) to block messages with .exe, .js, or foreign domains

✅ Block known malicious domains or country TLDs like .ru, .cn, .tk

✅ Use Regex keyword filters for lottery, win, free, reward, etc.

✅ Enable Defender for Office 365 to inspect attachments and apply Safe Attachments

✅ Regularly audit and test ETR policies

</details>






✅ SCENARIO 5: Email Spoofing and SPF Failures
<details> <summary><strong>🚨 Click here to expand</strong></summary>
📖 Real-World Context
An attacker sends a spoofed email appearing to come from the CEO of the company. The email urges the recipient to download a file related to payroll. On inspection, the email fails SPF (Sender Policy Framework) validation and has no DKIM (DomainKeys Identified Mail) or DMARC (Domain-based Message Authentication, Reporting & Conformance) signatures — clear signs of spoofing.

📧 Email Sample
From: ceo@company-hr.com
To: tom@company.com
Subject: ⚠️ Important: Download Payroll Document
Body: Please download the attached payroll update immediately.

❌ Red Flags
Suspicious external domain (looks similar to official)

SPF failed validation

No DKIM or DMARC present

Uses urgency tactic

Targeting employee from finance

🧪 Simulated Log File
Create log file: spoofed_email_spf_fail.log

sql
Copy
Edit
Timestamp | Sender | Recipient | Subject | SPFResult | DMARCResult | DKIMResult  
2025-06-18 09:45:23 | ceo@company-hr.com | tom@company.com | Important: Download Payroll | Fail | None | None  
Upload to VM under: C:\SecurityLogs\spoofed_email_spf_fail.log
Create DCR using Sentinel → Data Connectors → Custom Logs
Table Name: EmailHeaderLog_CL

📊 Dummy Log Table (EmailHeaderLog_CL)
Timestamp	Sender	Recipient	Subject	SPFResult	DMARCResult	DKIMResult
2025-06-18 09:45:23	ceo@company-hr.com	tom@company.com	Important: Download Payroll	Fail	None	None

🧠 KQL Detection Query
kql
Copy
Edit
EmailHeaderLog_CL
| where SPFResult == "Fail"                             // SPF failure indicates sender not authorized
| where DMARCResult == "None" or DKIMResult == "None"   // No domain validation or email signature
| project Timestamp, Sender, Recipient, Subject, SPFResult, DKIMResult, DMARCResult
📌 What Happens After Alert?
Alert appears in Microsoft Sentinel or Defender dashboard

Analyst investigates header details and confirms external spoof

Analysts may check similar sender addresses used recently

Incident ticket is created for potential spoofing attack

SOC team may verify if the domain company-hr.com is registered by attacker

🎯 MITRE ATT&CK Mapping
T1566.001 – Spearphishing via Service

T1585.001 – Spoofing Email Accounts

🔐 Prevention Techniques
✅ SPF (Sender Policy Framework): Add DNS TXT record to specify allowed IPs/domains to send email on your behalf

✅ DKIM (DomainKeys Identified Mail): Digitally signs emails with your domain

✅ DMARC (Domain-based Message Authentication): Specifies action for failed SPF/DKIM (none, quarantine, reject)

✅ Anti-phishing policies targeting VIP name spoofing and lookalike domains

✅ Block emails failing SPF from sending to internal distribution lists

🧯 Incident Response Steps
Tier 1 confirms alert from Sentinel

Tier 2 isolates recipient’s device and blocks sender

Header analysis is done to extract attack infrastructure

SOC creates transport rule to quarantine similar emails

IOC (Indicator of Compromise) added to threat intelligence feed

Awareness email sent to finance or executive group

</details>

---

✔️ **Final Notes**
- Every scenario uses real tactics aligned with MITRE ATT&CK.
- Logs, alerts, and queries are formatted to simulate SOC workflow.
- Perfect for portfolio projects and learning email security operations.



---

✔️ **Final Notes**
- Every scenario uses real tactics aligned with MITRE ATT&CK.
- Logs, alerts, and queries are formatted to simulate SOC workflow.
- Perfect for portfolio projects and learning email security operations.


