# PhishGuard: AI-Assisted Phishing Email Detection System

## Assessment Context

- Unit: ICT306 - Advanced Cybersecurity
- Assessment: Assessment 3 - Cybersecurity Project Implementation Following SSDLC
- Student Name: Marmik Karki
- Course: Bachelor of Information Technology (BIT)
- Semester: S1 2026

## Project Overview

PhishGuard is a secure desktop application that analyzes suspicious email content and identifies phishing indicators using heuristic and AI-assisted techniques. The project was implemented following the Secure Software Development Lifecycle (SSDLC), with cybersecurity controls integrated from requirements and design through testing, deployment, and operations.

The system includes secure login, role-based access control (RBAC), two-factor authentication (2FA), phishing detection, risk scoring, report generation, and audit logging.

## Objectives

- Develop a GUI-based phishing detector application using Python.
- Implement secure authentication with RBAC and 2FA.
- Detect phishing keywords, suspicious URLs, sender anomalies, and social engineering language.
- Produce risk scores and clear explanations for detected threats.
- Maintain security logs and exportable incident reports.
- Demonstrate SSDLC-aligned secure development and testing.

## Core Features

- Modern Tkinter-based user interface for easy live demonstration.
- Secure login with bcrypt-hashed passwords.
- OTP-based 2FA using TOTP.
- RBAC with admin, security analyst, and standard user roles.
- Detection engine with three modes:
  - Hybrid (default): heuristic plus ML signal.
  - Heuristic: rules-based checks only.
  - ML: model-only phishing probability.
- Heuristic checks include:
  - phishing keyword detection,
  - suspicious URL checks,
  - insecure HTTP link detection,
  - sender and reply-to mismatch,
  - urgency and social engineering language,
  - risky attachment indicators.
- Risk score output (0-100) with severity levels:
  - Low,
  - Medium,
  - High,
  - Critical.
- JSON and PDF report export.
- One-click SSDLC artifacts export:
  - STRIDE threat model,
  - security test case documentation.
- Security event logging and scan history.
- Session timeout enforcement.

## Tech Stack

- Python
- Tkinter (GUI)
- SQLite
- bcrypt
- pyotp
- cryptography
- reportlab

## Project Structure

```text
project/
|
|-- main.py
|-- auth/
|   |-- login.py
|   |-- register.py
|   |-- otp.py
|
|-- detection/
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
|   |-- test_detection.py
|
|-- reports/
```

## Demo Credentials

- admin / Admin@123
- analyst / Analyst@123
- user / User@123

For demo mode, complete username and password login first, then click Use Demo OTP on the OTP screen.

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
python -m unittest tests/test_detection.py
```

## SSDLC Mapping Summary

### Phase 1: Requirements
- Security requirements defined for confidentiality, integrity, and availability.
- RBAC, MFA, secure logging, and input validation requirements established.

### Phase 2: Threat Modeling
- STRIDE-based threat modeling used to identify spoofing, tampering, repudiation, information disclosure, denial of service, and privilege escalation risks.

### Phase 3: Secure Design
- Least privilege role model applied.
- Defense-in-depth architecture designed across authentication, validation, detection, storage, and logging.

### Phase 4: Secure Implementation
- Password hashing with bcrypt.
- Encrypted OTP secret storage using Fernet.
- Input validation and sanitization checks.
- Secure session handling with timeout behavior.

### Phase 5: Security Testing
- Detection unit tests included.
- Validation against phishing and legitimate sample content.
- Verification of role restrictions and export/reporting behavior.

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

PhishGuard demonstrates practical cybersecurity engineering by combining secure authentication, phishing detection, risk scoring, and security operations features in a single SSDLC-aligned implementation. The system is designed to be realistic, assessable, and effective for phishing awareness and defensive decision support.
