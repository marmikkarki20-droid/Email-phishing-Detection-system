# PhishGuard Architecture Diagram

---

## Figure 1: Secure Software Development Lifecycle (SSDLC)

```mermaid
flowchart LR
    P["Phase 1\nRequirements & Planning\n───────────\n• Define security requirements\n• Identify stakeholders\n• Establish RBAC policy\n• Scope phishing threats"]
    T["Phase 2\nThreat Modelling\n───────────\n• Apply STRIDE model\n• Identify attack vectors\n• DFD data flow review\n• Prioritise risks"]
    D["Phase 3\nSecure Design\n───────────\n• Layered architecture\n• Trust boundary mapping\n• Least privilege design\n• Encryption strategy"]
    I["Phase 4\nSecure Implementation\n───────────\n• bcrypt password hash\n• Fernet TOTP encrypt\n• Input validation\n• Parameterised SQL"]
    S["Phase 5\nSecurity Testing\n───────────\n• Unit tests (3 pass)\n• SQL injection checks\n• Auth bypass testing\n• Risk score validation"]
    DEP["Phase 6\nDeployment & Hardening\n───────────\n• Virtualenv isolation\n• Dependency pinning\n• Secrets never hardcoded\n• Minimal permissions"]
    M["Phase 7\nOperations & Monitoring\n───────────\n• Security event log\n• Audit trail in SQLite\n• Failed login tracking\n• Scan history retention"]

    P --> T --> D --> I --> S --> DEP --> M --> P

    style P   fill:#dbeafe,stroke:#1d4ed8,color:#1e3a5f,stroke-width:2px
    style T   fill:#ede9fe,stroke:#6d28d9,color:#2e1065,stroke-width:2px
    style D   fill:#fce7f3,stroke:#be185d,color:#500724,stroke-width:2px
    style I   fill:#d1fae5,stroke:#065f46,color:#022c22,stroke-width:2px
    style S   fill:#fef9c3,stroke:#854d0e,color:#3b1f02,stroke-width:2px
    style DEP fill:#fee2e2,stroke:#991b1b,color:#450a0a,stroke-width:2px
    style M   fill:#e0f2fe,stroke:#0369a1,color:#082f49,stroke-width:2px
```

**Figure 1: Secure Software Development Lifecycle (SSDLC) followed in PhishGuard.**

Figure 1 illustrates the seven SSDLC phases used throughout the PhishGuard project. Security was integrated into every stage including planning, threat modelling, implementation, testing, deployment, and monitoring. Each phase feeds into the next in a continuous cycle, ensuring security is never treated as an afterthought but as a core requirement embedded at every level of development.

| Phase | Name | Key PhishGuard Activity |
|---|---|---|
| 1 | Requirements & Planning | Defined phishing detection scope, RBAC policies, and stakeholder security expectations |
| 2 | Threat Modelling | Applied STRIDE framework; identified spoofing, injection, privilege escalation threats |
| 3 | Secure Design | Designed layered architecture with trust boundaries, encryption, and least privilege |
| 4 | Secure Implementation | bcrypt hashing, Fernet encryption, parameterised SQLite queries, input validation |
| 5 | Security Testing | 3 unit tests, SQL injection checks, authentication bypass testing, risk scoring validation |
| 6 | Deployment & Hardening | Virtualenv isolation, dependency pinning, no hardcoded secrets, minimal permissions |
| 7 | Operations & Monitoring | Security event logging, failed login tracking, scan history audit trail in SQLite |

---

## High-Level Secure Architecture

```mermaid
flowchart LR
    U[End User] --> GUI[Presentation Layer\nTkinter GUI in main.py]

    subgraph APP[Application Core]
        GUI --> AUTH[Authentication Layer\nauth/login.py\nauth/otp.py\nauth/register.py]
        GUI --> DET[Detection Layer\ndetection/risk_score.py]
        DET --> KEY[Keyword Detector\ndetection/keyword_detector.py]
        DET --> URL[URL Checker\ndetection/url_checker.py]
        DET --> ML[Naive Bayes ML Assist\ndetection/risk_score.py]
    end

    AUTH --> DB[(SQLite Security Data Layer\ndatabase/database.py)]
    DET --> DB
    GUI --> DB

    DB --> LOGS[logs/app.log\nSecurity Events and Audit Trail]
    GUI --> REPORT[Report Generation\nJSON PDF SSDLC Artifacts]
    REPORT --> RPT[reports/]

    classDef layer fill:#eef6ff,stroke:#245a9c,color:#0f1f35,stroke-width:1px;
    classDef data fill:#eafaf1,stroke:#1e7f45,color:#10351f,stroke-width:1px;
    classDef ext fill:#fff4e8,stroke:#a76011,color:#4d2b06,stroke-width:1px;

    class GUI,AUTH,DET,KEY,URL,ML layer;
    class DB,LOGS,REPORT,RPT data;
    class U ext;
```

## STRIDE Threat Model Diagram

```mermaid
flowchart TD
    subgraph UNTRUSTED["🔴 Untrusted Zone — External Input"]
        EMail["Email Content Input\n(Attacker-Controlled Data)"]
        Creds["Username & Password Input\n(Spoofing Risk)"]
    end

    subgraph BOUNDARY["🟡 Trust Boundary — Input Validation Layer"]
        VAL["Input Validation & Sanitisation\nGUI main.py"]
    end

    subgraph APP["🟢 Trusted Zone — Application Core"]
        AUTH["Authentication Module\nauth/login.py + auth/otp.py"]
        OTP["2FA TOTP Verification\npyotp + Fernet encryption"]
        DET["Detection Engine\ndetection/risk_score.py"]
        REP["Report Generator\nJSON / PDF / SSDLC"]
    end

    subgraph PERSIST["🔵 Persistence Boundary — Data Layer"]
        DB[("SQLite Database\ndatabase/database.py")]
        LOG["Security Event Log\nlogs/app.log"]
    end

    Creds -- "S: Spoofing\nForged credentials" --> VAL
    EMail -- "T: Tampering\nMalicious payload" --> VAL
    VAL --> AUTH
    VAL --> DET
    AUTH -- "E: Elevation of Privilege\nRole bypass attempt" --> OTP
    OTP --> DB
    DET --> DB
    DET --> REP
    REP -- "I: Information Disclosure\nSensitive data in export" --> LOG
    DB -- "R: Repudiation\nDeny actions" --> LOG
    VAL -- "D: Denial of Service\nOversized input flood" --> DET

    style UNTRUSTED fill:#fff1f2,stroke:#b42318,color:#661a12,stroke-width:2px
    style BOUNDARY fill:#fefce8,stroke:#854d0e,color:#3b1f02,stroke-width:2px
    style APP fill:#f0fdf4,stroke:#16a34a,color:#052e16,stroke-width:2px
    style PERSIST fill:#eff6ff,stroke:#1d4ed8,color:#1e3a5f,stroke-width:2px
```

**STRIDE Threat Mapping:**

| STRIDE Category | Label on Diagram | Attack Vector | PhishGuard Mitigation |
|---|---|---|---|
| **S** — Spoofing | Forged credentials | Fake username/password | bcrypt hashing + TOTP 2FA |
| **T** — Tampering | Malicious email payload | Injected script/SQL in email text | Input validation, parameterised SQL |
| **R** — Repudiation | Deny actions | User denies scanning malicious content | Timestamped security event log in SQLite |
| **I** — Information Disclosure | Sensitive data in export | OTP secret or hash leakage | Fernet encryption, no plaintext secrets |
| **D** — Denial of Service | Oversized input flood | Huge email bodies crashing parser | Input length cap in validation layer |
| **E** — Elevation of Privilege | Role bypass attempt | Standard user accessing admin events | RBAC checks enforced in GUI + DB layer |

## Short Explanation

- Presentation Layer handles user interaction and workflow control.
- Authentication Layer enforces password checks, OTP, and role policies.
- Detection Layer combines heuristic analysis with optional ML scoring.
- Data Layer securely stores users, scans, and security events.
- Reporting Layer exports JSON, PDF, and SSDLC evidence artifacts.
- Trust boundaries protect transitions from untrusted input to secure processing and storage.

---

## Figure 5: Secure Authentication and 2FA Workflow

```mermaid
flowchart TD
    START([User Launches PhishGuard]) --> LP[Login Screen\nEnter Username & Password]
    LP --> PV{bcrypt Password\nVerification}
    PV -- Fail --> LOG1[Log Failed Attempt\nto Security Events]
    LOG1 --> LOCK{Max Attempts\nReached?}
    LOCK -- Yes --> BLK[Account Locked\nSession Ended]
    LOCK -- No --> LP
    PV -- Pass --> OTP[OTP Screen\nEnter 6-Digit TOTP Code]
    OTP --> OV{pyotp TOTP\nVerification}
    OV -- Fail --> LOG2[Log OTP Failure\nto Security Events]
    LOG2 --> OTP
    OV -- Pass --> RBAC{RBAC Role\nCheck}
    RBAC -- Admin --> ADMIN[Full Dashboard\nAll Tabs + Security Events]
    RBAC -- Analyst --> ANALYST[Analyst Dashboard\nEmail Analysis + Scan History]
    RBAC -- User --> USER[Standard Dashboard\nEmail Analysis Only]
    ADMIN & ANALYST & USER --> SESS[Active Session\nPhishGuard Ready]
    SESS --> LOGOUT([User Logs Out\nSession Cleared])

    style START fill:#d1fae5,stroke:#065f46,color:#022c22,stroke-width:2px
    style LOGOUT fill:#fee2e2,stroke:#991b1b,color:#450a0a,stroke-width:2px
    style PV fill:#dbeafe,stroke:#1d4ed8,color:#1e3a5f,stroke-width:2px
    style OV fill:#dbeafe,stroke:#1d4ed8,color:#1e3a5f,stroke-width:2px
    style RBAC fill:#ede9fe,stroke:#6d28d9,color:#2e1065,stroke-width:2px
    style BLK fill:#fef9c3,stroke:#854d0e,color:#3b1f02,stroke-width:2px
    style LOG1 fill:#fff6f6,stroke:#b42318,color:#661a12,stroke-width:1px
    style LOG2 fill:#fff6f6,stroke:#b42318,color:#661a12,stroke-width:1px
```

**Figure 5: Secure Authentication and 2FA Workflow.**

Figure 5 demonstrates the secure authentication workflow implemented in PhishGuard. Users must pass password verification, OTP validation, and RBAC checks before access is granted. Failed attempts are logged to the Security Events audit trail. Role-based access control then determines which dashboard tabs and features are available to the authenticated user.

---

## Figure 6: System Workflow Diagram

```mermaid
flowchart TD
    A([Start]) --> B[User Authenticates\nPassword + OTP + RBAC]
    B --> C[Dashboard Loaded\nRole-Appropriate Tabs]
    C --> D[User Pastes Suspicious\nEmail Content into GUI]
    D --> E[Select Detection Mode\nHybrid / Heuristic / ML Only]
    E --> F[Input Validated\n& Sanitised]
    F --> G[Keyword Detector\ndetection/keyword_detector.py]
    F --> H[URL Checker\ndetection/url_checker.py]
    G & H --> I[Risk Score Aggregator\ndetection/risk_score.py]
    I --> J{ML Mode\nEnabled?}
    J -- Yes --> K[Naive Bayes Classifier\nGenerates ML Score]
    K --> L[Hybrid Score Merged\nHeuristic + ML Weight]
    J -- No --> L
    L --> M{Risk Level\nClassification}
    M -- HIGH --> N[HIGH RISK Result\nPhishing Indicators Listed]
    M -- MEDIUM --> O[MEDIUM RISK Result\nWarnings Listed]
    M -- LOW --> P[LOW RISK Result\nClean Assessment]
    N & O & P --> Q[Result Saved to\nScan History in SQLite]
    Q --> R{Export\nRequested?}
    R -- JSON --> S[Export JSON Report\nreports/]
    R -- PDF --> T[Export PDF Report\nreportlab]
    R -- SSDLC --> U[Export SSDLC Artifact\nreports/]
    R -- No --> V[User Reviews Results\nin Dashboard]
    S & T & U --> V
    V --> W([End / New Scan])

    style A fill:#d1fae5,stroke:#065f46,color:#022c22,stroke-width:2px
    style W fill:#d1fae5,stroke:#065f46,color:#022c22,stroke-width:2px
    style M fill:#dbeafe,stroke:#1d4ed8,color:#1e3a5f,stroke-width:2px
    style J fill:#ede9fe,stroke:#6d28d9,color:#2e1065,stroke-width:2px
    style N fill:#fee2e2,stroke:#991b1b,color:#450a0a,stroke-width:2px
    style O fill:#fef9c3,stroke:#854d0e,color:#3b1f02,stroke-width:2px
    style P fill:#d1fae5,stroke:#065f46,color:#022c22,stroke-width:2px
```

**Figure 6: PhishGuard System Workflow Diagram.**

Figure 6 shows the complete end-to-end workflow of the PhishGuard system. From authentication through email submission, detection processing, risk classification, result storage, and optional report export. The detection engine combines heuristic keyword/URL analysis with optional Naive Bayes ML scoring to produce a final risk level classification.

---

## Figure 7: Use Case Diagram

```mermaid
flowchart LR
    subgraph ACTORS[Actors]
        U([Standard User])
        AN([Security Analyst])
        AD([Administrator])
    end

    subgraph UC[PhishGuard Use Cases]
        UC1[Login with Password]
        UC2[Verify OTP / 2FA]
        UC3[Analyse Email Content]
        UC4[View Scan History]
        UC5[Export JSON Report]
        UC6[Export PDF Report]
        UC7[Export SSDLC Artifact]
        UC8[View Security Events]
        UC9[Manage User Accounts]
        UC10[Select Detection Mode]
    end

    U --> UC1
    U --> UC2
    U --> UC3
    U --> UC4
    U --> UC5
    U --> UC10

    AN --> UC1
    AN --> UC2
    AN --> UC3
    AN --> UC4
    AN --> UC5
    AN --> UC6
    AN --> UC7
    AN --> UC10

    AD --> UC1
    AD --> UC2
    AD --> UC3
    AD --> UC4
    AD --> UC5
    AD --> UC6
    AD --> UC7
    AD --> UC8
    AD --> UC9
    AD --> UC10

    style U fill:#dbeafe,stroke:#1d4ed8,color:#1e3a5f,stroke-width:2px
    style AN fill:#ede9fe,stroke:#6d28d9,color:#2e1065,stroke-width:2px
    style AD fill:#fce7f3,stroke:#be185d,color:#500724,stroke-width:2px
    style ACTORS fill:#f8fafc,stroke:#64748b,stroke-width:1px
    style UC fill:#f0fdf4,stroke:#16a34a,stroke-width:1px
```

**Figure 7: PhishGuard Use Case Diagram.**

Figure 7 presents the use case diagram showing interactions between the three system roles and available PhishGuard features. Standard Users can analyse emails and export basic reports. Security Analysts additionally export PDF and SSDLC artifacts. Administrators have full access including security event audit views and account management.

| Use Case | Standard User | Security Analyst | Administrator |
|---|---|---|---|
| Login with Password | ✅ | ✅ | ✅ |
| Verify OTP / 2FA | ✅ | ✅ | ✅ |
| Analyse Email Content | ✅ | ✅ | ✅ |
| View Scan History | ✅ | ✅ | ✅ |
| Export JSON Report | ✅ | ✅ | ✅ |
| Select Detection Mode | ✅ | ✅ | ✅ |
| Export PDF Report | ❌ | ✅ | ✅ |
| Export SSDLC Artifact | ❌ | ✅ | ✅ |
| View Security Events | ❌ | ❌ | ✅ |
| Manage User Accounts | ❌ | ❌ | ✅ |
