# PhishGuard: AI-Assisted Phishing Email Detection System

## Assessment Context

- Unit: ICT306 - Advanced Cybersecurity
- Assessment: Assessment 3 - Cybersecurity Project Implementation Following SSDLC
- Student Name: Marmik Karki
- Course: Bachelor of Information Technology (BIT)
- Semester: S1 2026

## Project Overview

PhishGuard is a secure desktop application that analyzes suspicious email content and identifies phishing indicators using heuristic and AI-assisted techniques. The project was implemented following the Secure Software Development Lifecycle (SSDLC), with cybersecurity controls integrated from requirements and design through testing, deployment, and operations.

The system includes account signup/login, email OTP verification, phishing detection, risk scoring, scan history, report generation, and security logging.

## Objectives

- Develop a GUI-based phishing detector application using Python.
- Implement account signup/login with secure password storage and email OTP verification.
- Detect phishing keywords, suspicious URLs, sender anomalies, and social engineering language.
- Produce risk scores and clear explanations for detected threats.
- Maintain security logs and exportable incident reports.
- Demonstrate SSDLC-aligned secure development and testing.

## Core Features

- Modern Tkinter-based user interface for easy live demonstration.
- Light/dark mode UI with dashboard-style risk summaries and recommended actions.
- Real signup flow for creating user accounts stored in SQLite.
- First local account becomes the admin account; later signups are standard users.
- Secure login with bcrypt-hashed passwords.
- Email OTP verification sent to the same email address used to sign in.
- Personal dashboard for scanning emails, reviewing scan history, and exporting reports.
- Admin security events view for authentication, OTP, scan, export, and session activity.
- Detection engine with three modes:
  - Hybrid (default): heuristic plus ML signal.
  - Heuristic: rules-based checks only.
  - ML: model-only phishing probability.
- Heuristic checks include:
  - phishing keyword detection,
  - suspicious URL checks,
  - insecure HTTP link detection,
  - brand/domain impersonation checks,
  - sender and reply-to mismatch,
  - sensitive information requests,
  - poor grammar/spelling patterns,
  - urgency and social engineering language,
  - risky attachment indicators.
- Risk score output (0-100) with severity levels:
  - Low,
  - Medium,
  - High,
  - Critical.
- `.txt` and `.eml` file loading for email analysis.
- Local scan history.
- JSON and PDF report export for investigation evidence.
- Security event logging for login, scan, and export activity.
- Session timeout enforcement.

## Tech Stack

- Python
- Tkinter (GUI)
- SQLite
- bcrypt
- reportlab

## Project Structure

```text
project/
|
|-- main.py
|-- auth/
|   |-- login.py
|   |-- register.py
|
|-- detection/
|   |-- analyzer.py
|   |-- keyword_detector.py
|   |-- url_checker.py
|   |-- risk_score.py
|
|-- database/
|   |-- database.py
|
|-- logs/
|   |-- app.log
|
|-- tests/
|   |-- test_auth_flow.py
|   |-- test_detection.py
|
|-- reports/
```

## Account Setup

Create a new account from the login screen using your email address. Signup accounts are stored in `data/phishguard.db` with bcrypt-hashed passwords.

The first local account is automatically promoted to `admin` so the project can demonstrate security monitoring. Later accounts are created as `standard_user`.

Email OTP delivery uses SMTP settings. The easiest setup is to copy the example config and fill in your email details:

```bash
cp smtp.env.example smtp.env
```

For Gmail, use an app password, not your normal Gmail password. The OTP is sent to the same email address entered at login.

You can also set the same values as environment variables instead:

```bash
export PHISHGUARD_SMTP_HOST="smtp.gmail.com"
export PHISHGUARD_SMTP_PORT="587"
export PHISHGUARD_SMTP_FROM="your-email@gmail.com"
export PHISHGUARD_SMTP_USERNAME="your-email@gmail.com"
export PHISHGUARD_SMTP_PASSWORD="your-app-password"
export PHISHGUARD_SMTP_TLS="1"
```

## How to Run

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Start the application:

```bash
python main.py
```

3. Run tests:

```bash
python -m unittest tests/test_detection.py tests/test_auth_flow.py
```

## Assignment Brief Coverage

| Requirement | Status | Implementation |
| --- | --- | --- |
| GUI-based Python tool | Covered | Tkinter desktop dashboard in `main.py` |
| Email content analysis | Covered | Subject/header/body text is scanned |
| Keyword and phrase detection | Covered | `detection/keyword_detector.py` |
| Suspicious link extraction/evaluation | Covered | `detection/url_checker.py` extracts and flags URLs |
| Non-secure HTTP links | Covered | `insecure_http` URL indicator |
| URL shorteners | Covered | `url_shortener` indicator |
| Mismatched/impersonation domains | Covered | sender/reply-to mismatch and brand impersonation checks |
| Heuristic pattern detection | Covered | urgency, sensitive data requests, grammar/spelling, attachment-risk language |
| Risk score 0-100 | Covered | `AnalysisResult.score` and GUI risk meter |
| User-friendly result display | Covered | personal dashboard, score, severity, indicators, URLs, explanation, and recommended actions |
| Educational insight/report | Covered | explanation text and suggested actions after analysis |
| `.txt` and `.eml` file support | Covered | Open File workflow parses text and email files |
| Signup/login with stored credentials | Covered | signup creates bcrypt-hashed SQLite user records |
| Email OTP verification | Covered | OTP is sent to the same email address used for login |
| Admin/security logging | Covered | admin-only Security Events tab displays local audit events |
| Testing with phishing/legitimate samples | Covered | unit tests plus built-in demo samples |

Suggested extras included: account signup/login, email OTP verification, lightweight ML signal, PDF/JSON report generation, dark mode, scan history, and security logging. Real-time Gmail/Outlook integration and live external reputation APIs are intentionally left as future enhancements because they require third-party service setup.

## SSDLC Mapping Summary

### Phase 1: Requirements
- Security requirements defined for confidentiality, integrity, and availability.
- Secure login, email OTP, secure logging, report export, and input validation requirements established.

### Phase 2: Threat Modeling
- STRIDE-based threat modeling used to identify spoofing, tampering, repudiation, information disclosure, denial of service, and privilege escalation risks.

### Phase 3: Secure Design
- Defense-in-depth architecture designed across authentication, validation, detection, storage, and logging.

### Phase 4: Secure Implementation
- Password hashing with bcrypt.
- Input validation and sanitization checks.
- Secure session handling with timeout behavior.

### Phase 5: Security Testing
- Detection unit tests included.
- Validation against phishing and legitimate sample content.
- Verification of signup/login and detection behavior.

### Phases 6-7: Deployment and Operations
- Security logging enabled.
- Report generation for investigation and evidence.
- Maintainable modular architecture for future updates.

## Limitations

- No direct live enterprise mail server integration.
- No production cloud deployment in this academic implementation.
- ML component is lightweight and demo-focused.

## Future Enhancements

- Integrate external threat intelligence and URL reputation APIs.
- Add attachment malware scanning.
- Add real-time email stream monitoring.
- Train a larger ML model with expanded phishing datasets.
- Add cloud deployment pipeline and hardened production profile.

## Conclusion

PhishGuard demonstrates practical cybersecurity engineering by combining secure authentication, phishing detection, risk scoring, scan history, and reporting in a single SSDLC-aligned implementation. The system is designed to be realistic, assessable, and effective for phishing awareness and defensive decision support.
