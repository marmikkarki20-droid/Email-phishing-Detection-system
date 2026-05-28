# PhishGuard Presentation Speaker Notes

## Slide 1 - Project Title and Objectives
Introduce PhishGuard as an AI-assisted phishing email detection system built for ICT306 Assessment 3. Explain that the aim is not only to detect phishing emails, but to demonstrate a security-first SSDLC approach with authentication, 2FA, logging, testing, and report generation.

## Slide 2 - Problem and Security Context
Explain why phishing remains a major cybersecurity risk. Attackers use urgency, impersonation, suspicious links, and credential-harvesting messages. PhishGuard addresses this by giving users a local tool that explains why an email is risky instead of only showing a simple yes/no result.

## Slide 3 - Threat Model Overview
Walk through the high-level flow: user input enters the Tkinter GUI, moves through authentication and detection logic, and then stores scan/security data in SQLite. Mention the STRIDE threats considered, especially spoofing, tampering, information disclosure, denial of service, and elevation of privilege.

## Slide 4 - Secure Design Decisions
Describe the layered security design. Passwords use bcrypt, OTP adds a second authentication step, RBAC limits admin-only views, input validation rejects unsafe content, and audit logging keeps a trail of important security actions.

## Slide 5 - Implementation Highlights
Explain the main modules. `main.py` controls the GUI and workflow, `auth/` handles login, registration, and OTP, `database/` handles SQLite persistence, and `detection/` performs keyword, URL, sender, and risk scoring checks. Mention that hybrid mode combines heuristic evidence with a lightweight ML-style signal.

## Slide 6 - Security Testing Results
Discuss the testing evidence: detection tests, authentication flow tests, input validation, scan logging, session behavior, and report export checks. State that the current test command passed 7 unit tests.

## Slide 7 - Demo: Live Security Features
Use this slide while demonstrating the app. Show login and email OTP, paste or load an email, run analysis, review score/indicators/actions, then show scan history, admin security events, and report export.

## Slide 8 - Lessons Learned and Future Enhancements
Summarize the main lesson: security has to be designed from the start, not added after implementation. Future improvements include threat intelligence APIs, attachment scanning, live mailbox integration, a stronger trained ML model, and a production deployment profile.
