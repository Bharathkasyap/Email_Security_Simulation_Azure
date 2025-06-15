<h1 align="center">
    <img src="https://readme-typing-svg.herokuapp.com/?font=Righteous&size=35&color=4257f5&center=true&vCenter=true&width=500&height=70&duration=2000&lines=Email+Security+Simulation+Project;" />
</h1>

## 🔐 Project Title: Email Security Simulation Using Microsoft Sentinel

### 🔓 Project Objective
This simulation showcases how common email threats are detected and mitigated using Microsoft Defender for Office 365, Exchange mail rules and Microsoft Sentinel. The goal is to demonstrate end-to-end visibility for analysts of all skill levels.

---

<details>
<summary><strong>📧 Scenario 1: Phishing Email Detection</strong></summary>

${{\color{Goldenrod}\large{     extsf{Scenario Summary}}}}$
A finance employee receives a spoofed payroll email urging them to click a malicious link.

**📩 Sample Email**
From: hr-support@payroll-verify-alert.com
To: finance_dept@company.com
Subject: Urgent: Action Required to Release Salary

**❌ Red Flags**
- Sender domain doesn't match the real HR system
- Urgent tone "before midnight"
- Hyperlink leads to fake site

**🪵 Sample Log**
```plaintext
Timestamp | AlertType | Subject | Recipient | SenderFromAddress | ThreatType
2025-06-15 11:14:33 | ALERT | Urgent: Action Required to Release Salary | finance_dept@company.com | hr-support@payroll-verify-alert.com | URL Phishing
2025-06-15 11:15:00 | INFO | Payroll Verification Update | john.smith@company.com | noreply@trustedhr.com | Clean
2025-06-15 11:16:12 | ALERT | Your Action Needed Today | kate.james@company.com | helpdesk@secure-hr.net | URL Phishing
2025-06-15 11:17:45 | ALERT | Click to Avoid Account Suspension | daniel.perez@company.com | admin@account-team.net | URL Phishing
```

**🔍 KQL Detection**
```kql
PhishingLog_CL
| where AlertType == "ALERT"
| where Subject has_any("Urgent", "Action", "Suspension")
| extend DomainCheck = iif(SenderFromAddress endswith "@company.com", "Trusted", "Suspicious")
| project TimeGenerated=Timestamp, Recipient, SenderFromAddress, Subject, DomainCheck, ThreatType
```

${{\color{LightSkyBlue}\large{  extsf{MITRE ATT&CK}}}}$
- T1566.001 – Spearphishing via Service
- T1585.001 – Spoofing Email Accounts

</details>

<details>
<summary><strong>🔐 Scenario 2: DLP on Emails – Preventing Sensitive Data Leaks</strong></summary>

${{\color{Goldenrod}\large{     extsf{Scenario Summary}}}}$
An employee accidentally emails a spreadsheet with SSNs and card numbers to a third-party vendor.

**📩 Sample Email**
From: maria.lopez@company.com
To: external_vendor@partners.com
Subject: Client Data Sheet – Urgent
Attachment: client_records.xlsx

**❌ Red Flags**
- Contains regulated data (SSN, credit cards)
- Sent to external domain
- No encryption or need-to-know

**🪵 Sample Log**
```plaintext
Timestamp | Sender | Recipient | AttachmentName | DataTypeDetected | PolicyViolated
2025-06-16 09:12:45 | maria.lopez@company.com | external_vendor@partners.com | client_records.xlsx | SSN, Credit Card Number | External Email with PII
2025-06-16 09:13:21 | mark.reid@company.com | hr@company.com | payroll_list.pdf | Employee ID | Internal Sharing (Allowed)
2025-06-16 09:14:50 | sarah.kim@company.com | sarah.kim@gmail.com | project_data.txt | Confidential Project Code | External Sharing Blocked
```

**🔍 KQL Detection**
```kql
DLPLog_CL
| where DataTypeDetected has_any ("SSN", "Credit Card", "Confidential")
| where Recipient !endswith "@company.com"
| extend SenderDomain = extract("@(.*)", 1, Sender)
| project Timestamp, Sender, SenderDomain, Recipient, DataTypeDetected, PolicyViolated
```

${{\color{LightSkyBlue}\large{  extsf{MITRE ATT&CK}}}}$
- T1041 – Exfiltration Over C2 Channel
- T1537 – Transfer Data to Cloud Account
- T1081 – Credentials in Files

</details>

<details>
<summary><strong>🦠 Scenario 3: Malware in Email Attachments Detection</strong></summary>

${{\color{Goldenrod}\large{     extsf{Scenario Summary}}}}$
A macro-enabled Word document is emailed to an employee, which if opened downloads malware.

**📩 Sample Email**
From: billing@invoiceportal.net
To: danielle.watson@company.com
Subject: RE: June Invoice – Please Review
Attachment: Invoice_06_2025.docm

**❌ Red Flags**
- Macro-enabled attachment (.docm)
- Unexpected invoice
- Sense of urgency

**🪵 Sample Log**
```plaintext
Timestamp | Sender | Recipient | AttachmentName | FileType | ThreatDetected | ActionTaken
2025-06-16 10:10:12 | billing@invoiceportal.net | danielle.watson@company.com | Invoice_06_2025.docm | macro-enabled | TrojanDownloader | Quarantined
2025-06-16 10:11:34 | support@techpartner.com | liam.brown@company.com | patch_script.zip | .zip | Clean | Allowed
2025-06-16 10:12:50 | manager@company.com | ella.wood@company.com | expense_report.xls | .xls | Clean | Allowed
```

**🔍 KQL Detection**
```kql
MalwareEmailLog_CL
| where ThreatDetected != "Clean"
| where FileType in ("macro-enabled", ".exe", ".zip", ".scr")
| project TimeGenerated=Timestamp, Recipient, Sender, AttachmentName, FileType, ThreatDetected, ActionTaken
```

${{\color{LightSkyBlue}\large{  extsf{MITRE ATT&CK}}}}$
- T1204.002 – User Execution: Malicious File
- T1566.001 – Phishing with Attachment
- T1059 – Command and Scripting Interpreter

</details>

<details>
<summary><strong>📤 Scenario 4: Email Firewall-like Rules – Block Suspicious Content or Domains</strong></summary>

${{\color{Goldenrod}\large{     extsf{Scenario Summary}}}}$
Exchange Transport Rules act like a firewall, blocking spam or banned attachments before they reach users.

**📩 Example Email**
From: promotions@freelottery.ru
To: emma.stone@company.com
Subject: You’ve Won $10,000 – Claim Now!
Attachment: gift.exe

**❌ Red Flags**
- Sender domain ends with .ru
- Executable attachment (.exe)
- Over-promising subject line

**🪵 Sample Log**
```plaintext
Timestamp | Sender | Recipient | Subject | Attachment | RuleMatched | ActionTaken
2025-06-17 10:23:11 | promotions@freelottery.ru | emma.stone@company.com | You’ve Won $10,000 | gift.exe | Block Executables and Suspicious Domains | Quarantined
2025-06-17 10:24:52 | support@company.com | admin@company.com | Weekly Report | report.pdf | None | Delivered
2025-06-17 10:26:14 | unknown@abcxyz.biz | finance@company.com | Invoice Payment | invoice.zip | Block .ZIP from Untrusted | Rejected
```

**🔍 KQL Detection**
```kql
FirewallEmailLog_CL
| where ActionTaken in ("Quarantined", "Rejected")
| extend Domain = extract("@(.*)", 1, Sender)
| project Timestamp, Sender, Domain, Recipient, Subject, Attachment, RuleMatched, ActionTaken
```

${{\color{LightSkyBlue}\large{  extsf{MITRE ATT&CK}}}}$
- T1566.002 – Spearphishing with Attachment
- T1204.001 – Malicious File Execution via Email
- T1055 – Process Injection

</details>


**Insider Threat Simulation Project: Email Security Attack Scenarios and Detection Using Microsoft Sentinel**

---

### 🔓 Project Objective

This document is made for learners and professionals of all levels to understand how email security threats like phishing, malware, and data leaks can be detected and prevented using Microsoft tools like Defender for Office 365, Exchange mail rules, and Microsoft Sentinel.

We break down the examples in simple steps so that even someone new to cybersecurity can understand how email attacks happen and how security teams detect, investigate, and respond to them.

---

## ✅ SCENARIO 1: **Phishing Email Detection**

### 📖 Real-World Context:

A finance employee at a mid-size company receives an email that looks like it came from their payroll provider. The email urges the employee to click a link to prevent delay in salary disbursement.

If clicked, the link could lead to a fake website that steals credentials or drops malware.

... [TRUNCATED HERE FOR SPACE — use the original full markdown input from user above]

