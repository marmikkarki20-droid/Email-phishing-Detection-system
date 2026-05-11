# Figure 1: SSDLC Lifecycle Diagram

## Figure 1: Secure Software Development Lifecycle (SSDLC) followed in PhishGuard

```mermaid
flowchart LR
    P["🔹 Phase 1\nRequirements\n& Planning\n───────────\n• Define security\n  requirements\n• Identify stakeholders\n• Establish RBAC policy\n• Scope phishing threats"]
    T["🔹 Phase 2\nThreat\nModelling\n───────────\n• Apply STRIDE model\n• Identify attack vectors\n• DFD data flow review\n• Prioritise risks"]
    D["🔹 Phase 3\nSecure\nDesign\n───────────\n• Layered architecture\n• Trust boundary mapping\n• Least privilege design\n• Encryption strategy"]
    I["🔹 Phase 4\nSecure\nImplementation\n───────────\n• bcrypt password hash\n• Fernet TOTP encrypt\n• Input validation\n• Parameterised SQL"]
    S["🔹 Phase 5\nSecurity\nTesting\n───────────\n• Unit tests (3 pass)\n• SQL injection checks\n• Auth bypass testing\n• Risk score validation"]
    DEP["🔹 Phase 6\nDeployment\n& Hardening\n───────────\n• Virtualenv isolation\n• Dependency pinning\n• Secrets never hardcoded\n• Minimal permissions"]
    M["🔹 Phase 7\nOperations\n& Monitoring\n───────────\n• Security event log\n• Audit trail in SQLite\n• Failed login tracking\n• Scan history retention"]

    P --> T --> D --> I --> S --> DEP --> M --> P

    style P   fill:#dbeafe,stroke:#1d4ed8,color:#1e3a5f,stroke-width:2px
    style T   fill:#ede9fe,stroke:#6d28d9,color:#2e1065,stroke-width:2px
    style D   fill:#fce7f3,stroke:#be185d,color:#500724,stroke-width:2px
    style I   fill:#d1fae5,stroke:#065f46,color:#022c22,stroke-width:2px
    style S   fill:#fef9c3,stroke:#854d0e,color:#3b1f02,stroke-width:2px
    style DEP fill:#fee2e2,stroke:#991b1b,color:#450a0a,stroke-width:2px
    style M   fill:#e0f2fe,stroke:#0369a1,color:#082f49,stroke-width:2px
```

---

**Caption:** Figure 1: Secure Software Development Lifecycle (SSDLC) followed in PhishGuard.

**Explanation:** Figure 1 illustrates the seven SSDLC phases used throughout the PhishGuard project. Security was integrated into every stage including planning, threat modelling, implementation, testing, deployment, and monitoring. Each phase feeds into the next in a continuous cycle, ensuring security is never treated as an afterthought but as a core requirement embedded at every level of development.

| Phase | Name | Key PhishGuard Activity |
|---|---|---|
| 1 | Requirements & Planning | Defined phishing detection scope, RBAC policies, and stakeholder security expectations |
| 2 | Threat Modelling | Applied STRIDE framework; identified spoofing, injection, privilege escalation threats |
| 3 | Secure Design | Designed layered architecture with trust boundaries, encryption, and least privilege |
| 4 | Secure Implementation | bcrypt hashing, Fernet encryption, parameterised SQLite queries, input validation |
| 5 | Security Testing | 3 unit tests, SQL injection checks, authentication bypass testing, risk scoring validation |
| 6 | Deployment & Hardening | Virtualenv isolation, dependency pinning, no hardcoded secrets, minimal permissions |
| 7 | Operations & Monitoring | Security event logging, failed login tracking, scan history audit trail in SQLite |
