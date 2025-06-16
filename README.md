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

## <details><summary>✅ SCENARIO 2: Data Loss Prevention (DLP) on Emails</summary>

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

## <details><summary>✅ SCENARIO 3: Malware in Email Attachments</summary>

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

## <details><summary>✅ SCENARIO 4: Email Firewall (ETRs)</summary>

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

## <details><summary>✅ SCENARIO 5: Email Spoofing and SPF Failures</summary>

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

### 🛡️ Prevention:
- Add SPF DNS record with valid senders
- Enable DKIM key signing
- Setup DMARC policy to quarantine/reject

</details>

---

### ✅ Summary

This simulation set helps SOC analysts understand and test:
- Threat detection via logs
- Real SOC playbook steps
- MITRE coverage and incident response actions


















<h1 align="center">
    <img src="https://readme-typing-svg.herokuapp.com/?font=Righteous&size=35&color=2ea44f&center=true&vCenter=true&width=800&height=70&duration=3000&lines=Email+Security+Detection+Simulation+Project" />
</h1>

---

# 🔐 Insider Threat Simulation Project: Email Security Attack Scenarios and Detection Using Microsoft Sentinel

This project helps analysts simulate and detect email-based cyberattacks like phishing, spoofing, DLP violations, and malware attachments using Microsoft Defender, Sentinel, Exchange, and Purview.

The content is written to be understood by beginners (including students) and useful to professionals building blue team portfolios.

---

<details>
<summary><strong>✅ Scenario 1: Phishing Email Detection</strong></summary>

### 📖 Real-World Scenario:
A fake HR alert is received by the finance team, urging urgent verification of payroll. If clicked, it redirects users to a phishing site that steals credentials.

---

### ❌ Red Flags:

- External spoofed domain
- Urgency (salary delay)
- Fake link
- Spoofed HR impersonation

---

### 👨‍💻 Analyst Action:

1. **Create file** `phishing_alert.log`

```
Timestamp | AlertType | Subject | Recipient | SenderFromAddress | ThreatType
2025-06-15 11:14:33 | ALERT | Urgent: Action Required to Release Salary | finance_dept@company.com | hr-support@payroll-verify-alert.com | URL Phishing
2025-06-15 11:15:00 | INFO | Payroll Verification Update | john.smith@company.com | noreply@trustedhr.com | Clean
2025-06-15 11:16:12 | ALERT | Your Action Needed Today | kate.james@company.com | helpdesk@secure-hr.net | URL Phishing
```

2. **Upload to VM:**  
`C:\SecurityLogs\phishing_alert.log`

3. **Create DCR in Sentinel:**  
Microsoft Sentinel > Data Connectors > Custom Logs  
Table name: `PhishingLog_CL`

---

### 📊 Dummy Detection Table

| Timestamp           | AlertType | Subject                             | Recipient               | SenderFromAddress                   | ThreatType     |
|---------------------|-----------|--------------------------------------|--------------------------|--------------------------------------|----------------|
| 2025-06-15 11:14:33 | ALERT     | Urgent: Action Required to Release Salary | finance_dept@company.com | hr-support@payroll-verify-alert.com | URL Phishing   |
| 2025-06-15 11:16:12 | ALERT     | Your Action Needed Today             | kate.james@company.com   | helpdesk@secure-hr.net              | URL Phishing   |

---

### 💬 KQL Detection:

```kql
PhishingLog_CL
| where AlertType == "ALERT"
| where Subject has_any("Urgent", "Action", "Suspension")
| extend DomainCheck = iif(SenderFromAddress endswith "@company.com", "Trusted", "Suspicious")
| project TimeGenerated=Timestamp, Recipient, SenderFromAddress, Subject, DomainCheck, ThreatType
```

---

### 🔍 Analyst View:
- Query shows risky emails
- Highlights untrusted senders
- Flags keywords like *Urgent*, *Action*

---

### 🧠 MITRE ATT&CK Mapping

- T1566.001: Spearphishing via Service
- T1585.001: Email Spoofing

---

### 🛡️ Prevention Techniques

- Safe Links (Defender)
- Anti-phishing policies
- SPF, DKIM, DMARC setup

---

### 🧯 Incident Response

- Tier 1 tags phishing alert
- Tier 2 isolates user device
- Sandbox test of link
- Transport rule updated
- IOC reported

</details>

---

<details>
<summary><strong>✅ Scenario 2: DLP Violation on Email Attachments</strong></summary>

### 📖 Real-World Scenario:
An employee mistakenly shares SSNs and card details to an external vendor via Excel file.

---

### ❌ Red Flags

- Sensitive data (SSNs, credit cards)
- External domain
- No encryption
- Violates DLP policy

---

### 👨‍💻 Analyst Action:

1. Create `dlp_email_log.log`

```
Timestamp | Sender | Recipient | AttachmentName | DataTypeDetected | PolicyViolated
2025-06-16 09:12:45 | maria.lopez@company.com | external_vendor@partners.com | client_records.xlsx | SSN, Credit Card Number | External Email with PII
```

2. Upload to: `C:\SecurityLogs\dlp_email_log.log`  
3. Create DCR → `DLPLog_CL`

---

### 💬 KQL Detection

```kql
DLPLog_CL
| where DataTypeDetected has_any("SSN", "Credit Card")
| where Recipient !endswith "@company.com"
| extend SenderDomain = extract("@(.*)", 1, Sender)
| project Timestamp, Sender, SenderDomain, Recipient, DataTypeDetected, PolicyViolated
```

---

### 🧠 MITRE ATT&CK Mapping

- T1041: Exfiltration Over C2
- T1081: Credentials in Files

---

### 🛡️ Prevention Techniques

- Purview DLP block rules
- Auto-labeling PII
- Education

---

### 🧯 Incident Response

- Alert to Sentinel
- SOC validates intent
- HR/legal looped in
- Domain blocked

</details>

---

More scenarios can be added (e.g., spoofing, email firewall rules).  
This README can be previewed properly in GitHub markdown renderers.


