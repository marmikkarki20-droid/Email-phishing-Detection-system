# Security Test Cases - PhishGuard

Generated: 2026-05-10

## Authentication and Authorization

| ID | Test Case | Steps | Expected Result |
|---|---|---|---|
| AUTH-01 | Valid login + valid OTP | Login with known account and current OTP | Access granted to dashboard |
| AUTH-02 | Invalid password | Login with wrong password | Access denied and event logged |
| AUTH-03 | Invalid OTP | Enter wrong 6-digit OTP | OTP rejected and event logged |
| AUTH-04 | RBAC on security events | Login as standard user and open event tab | Access denied message shown |
| AUTH-05 | Session timeout | Wait for timeout period | Session ends and user returns to login |

## Input Validation

| ID | Test Case | Steps | Expected Result |
|---|---|---|---|
| INP-01 | Empty email body | Click Analyze without content | Validation blocks request |
| INP-02 | Oversized email body | Paste text over max length | Validation blocks request |
| INP-03 | Script payload input | Include <script>alert(1)</script> | Input rejected and logged |

## Detection and Scoring

| ID | Test Case | Steps | Expected Result |
|---|---|---|---|
| DET-01 | High-risk phishing sample | Load phishing sample and analyze | Score >= 60 and High/Critical risk |
| DET-02 | Legitimate sample | Load legit sample and analyze | Score lower than phishing sample |
| DET-03 | URL shortener and HTTP | Analyze content with bit.ly + http:// | Indicators include URL shortener and insecure link |
| DET-04 | Sender mismatch | Use different From and Reply-To domains | Sender mismatch indicator detected |

## Reporting and Audit

| ID | Test Case | Steps | Expected Result |
|---|---|---|---|
| RPT-01 | JSON export | Analyze then export JSON | JSON file created under reports |
| RPT-02 | PDF export | Analyze then export PDF | PDF file created under reports |
| RPT-03 | SSDLC docs export | Click Generate SSDLC Artifacts | Threat model and test case files generated |
