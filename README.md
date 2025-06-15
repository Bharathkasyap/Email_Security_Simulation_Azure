
<h1 align="center">
    <img src="https://readme-typing-svg.herokuapp.com/?font=Righteous&size=35&color=4257f5&center=true&vCenter=true&width=500&height=70&duration=2000&lines=E/Email+Security+Simulation+Project+;" />
</h1>

## 🔐 Project Title: Email Security Simulation Using Microsoft Sentinel

### Description
A beginner-friendly, industry-ready simulation of email threats and SOC responses using Microsoft 365, Sentinel, Defender for Office 365, and Purview DLP.

---

<details>
<summary><strong>📧 Scenario 1: Phishing Email Detection</strong></summary>

${{\color{Goldenrod}\large{	extsf{Scenario Summary}}}}\$  
A spoofed email tricks an employee to click a link, redirecting them to a fake login page. Defender flags the link, Sentinel detects it.

**📩 Sample Email**  
From: hr-support@payroll-verify-alert.com  
To: finance_dept@company.com  
Subject: Urgent: Action Required to Release Salary  

**❌ Red Flags**  
- Suspicious domain  
- Urgent tone  
- Fake hyperlink  

**🪵 Sample Log**
```plaintext
Timestamp | AlertType | Subject | Recipient | SenderFromAddress | ThreatType
2025-06-15 11:14:33 | ALERT | Urgent: Action Required to Release Salary | finance_dept@company.com | hr-support@payroll-verify-alert.com | URL Phishing
```
**🔍 KQL Detection**
```kql
PhishingLog_CL
| where AlertType == "ALERT"
| where Subject has_any("Urgent", "Action", "Suspension")
| extend DomainCheck = iif(SenderFromAddress endswith "@company.com", "Trusted", "Suspicious")
| project TimeGenerated=Timestamp, Recipient, SenderFromAddress, Subject, DomainCheck, ThreatType
```

${{\color{LightSkyBlue}\large{	extsf{MITRE ATT&CK}}}}\$  
- T1566.001: Spearphishing via Service  
- T1585.001: Email Spoofing  

</details>

<details>
<summary><strong>🔐 Scenario 2: Email DLP – Sensitive Data Leak Prevention</strong></summary>

${{\color{Goldenrod}\large{	extsf{Scenario Summary}}}}\$  
An employee sends a spreadsheet with SSNs and card data to a third-party vendor.

**📩 Sample Email**  
From: maria.lopez@company.com  
To: external_vendor@partners.com  
Subject: Client Data Sheet – Urgent  
Attachment: client_records.xlsx  

**🪵 Sample Log**
```plaintext
Timestamp | Sender | Recipient | AttachmentName | DataTypeDetected | PolicyViolated
2025-06-16 09:12:45 | maria.lopez@company.com | external_vendor@partners.com | client_records.xlsx | SSN, Credit Card Number | External Email with PII
```

**🔍 KQL Detection**
```kql
DLPLog_CL
| where DataTypeDetected has_any ("SSN", "Credit Card", "Confidential")
| where Recipient !endswith "@company.com"
| extend SenderDomain = extract("@(.*)", 1, Sender)
| project Timestamp, Sender, SenderDomain, Recipient, DataTypeDetected, PolicyViolated
```

${{\color{LightSkyBlue}\large{	extsf{MITRE ATT&CK}}}}\$  
- T1041: Exfiltration Over C2 Channel  
- T1537: Transfer Data to Cloud  
</details>

<details>
<summary><strong>🦠 Scenario 3: Malware in Email Attachments</strong></summary>

${{\color{Goldenrod}\large{	extsf{Scenario Summary}}}}\$  
An attacker sends a PDF with an embedded macro to drop malware.

**🪵 Sample Log**
```plaintext
Timestamp | Sender | Attachment | MalwareDetected | SandboxResult | ActionTaken
2025-06-17 10:32:22 | unknown@freemail.ru | Invoice_1090.pdf | TrojanDownloader | Detonated & Confirmed | Quarantined
```

**🔍 KQL Detection**
```kql
EmailAttachmentInfo
| where MalwareDetected != ""
| where SandboxResult contains "Confirmed"
| project Timestamp, Sender, Attachment, MalwareDetected, ActionTaken
```

${{\color{LightSkyBlue}\large{	extsf{MITRE ATT&CK}}}}\$  
- T1204.002: Malicious File Execution  
- T1059.005: Visual Basic Macros  
</details>

<details>
<summary><strong>📤 Scenario 4: Email Firewall Rules (Transport Rules)</strong></summary>

${{\color{Goldenrod}\large{	extsf{Scenario Summary}}}}\$  
A rule blocks outgoing mail that includes banned terms or domains.

**🪵 Example Transport Rule**  
- Block outbound messages if subject contains "bank credentials"  
- Block to domains like gmail.com if PII is found

**🔍 KQL Insight (via TransportRuleLog_CL)**
```kql
TransportRuleLog_CL
| where RuleName has "Block External with PII"
| where Action == "Reject"
| project Timestamp, Sender, Recipient, RuleName, TriggerTerms
```

${{\color{LightSkyBlue}\large{	extsf{Use Cases}}}}\$  
- Prevent leakage of internal financials  
- Block known risky domains  
</details>

<details>
<summary><strong>🎭 Scenario 5: Email Spoofing + SPF/DKIM/DMARC Failures</strong></summary>

${{\color{Goldenrod}\large{	extsf{Scenario Summary}}}}\$  
Spoofed email pretending to be the CEO bypasses M365 mail filters due to missing DNS authentication.

**🪵 Sample Log**
```plaintext
Timestamp | Sender | SPFResult | DKIMResult | DMARCResult | Action
2025-06-18 08:45:01 | ceo@company.com | fail | fail | fail | Quarantined
```

**🔍 KQL Detection**
```kql
EmailEvents
| where SPFResult == "fail" or DKIMResult == "fail" or DMARCResult == "fail"
| where Sender endswith "@company.com"
| project Timestamp, Sender, SPFResult, DKIMResult, DMARCResult, Action
```

${{\color{LightSkyBlue}\large{	extsf{MITRE ATT&CK}}}}\$  
- T1585.002: Email Address Spoofing  
- T1566.001: Spearphishing  
</details>
