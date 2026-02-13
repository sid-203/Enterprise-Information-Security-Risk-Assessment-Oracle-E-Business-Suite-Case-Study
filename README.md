# Information Security: GDPR Compliance & Incident Response

A comprehensive security and privacy compliance framework for high-risk biometric surveillance systems (CCTV, Facial Recognition Technology, and centralised contact tracing), including comparative framework analysis (ISO 27001, Cyber Essentials, NIST CSF 2.0, COBIT) and a detailed incident response case study analyzing the 2025 Oracle E-Business Suite CVE-2025-61882 breach.

## Table of Contents

- [Project Overview](#project-overview)
- [Chapter 1: Data Protection Compliance](#chapter-1-data-protection-compliance)
  - [Data Protection by Design & Default (DPbD)](#data-protection-by-design--default-dpbd)
  - [Framework Comparison Analysis](#framework-comparison-analysis)
  - [Security Implementation & Incident Response](#security-implementation--incident-response)
- [Chapter 2: Oracle EBS Breach Case Study](#chapter-2-oracle-ebs-breach-case-study)
  - [CVE-2025-61882 Analysis](#cve-2025-61882-analysis)
  - [Attacker TTPs & Defensive Countermeasures](#attacker-ttps--defensive-countermeasures)
  - [Risk Assessment & Mitigation Strategy](#risk-assessment--mitigation-strategy)
- [Key Deliverables](#key-deliverables)
- [Academic Context](#academic-context)
- [References](#references)
- [Author](#author)

## Project Overview

This assignment addresses critical challenges in deploying **high-risk biometric surveillance systems** while maintaining compliance with **UK GDPR**, implementing **layered security controls**, and establishing **robust incident response capabilities**.

### System Scope

**Proposed Solution Components:**
1. **CCTV Network**: Video surveillance infrastructure
2. **Facial Recognition Technology (FRT)**: Biometric identification system
3. **Centralised Contact Tracing**: Database for tracking interactions

**Key Challenges:**
- High-impact privacy risks (biometric special category data)
- Resource-constrained operational environment
- Complex regulatory landscape (UK GDPR Article 25, ICO guidance)
- Multi-vendor security assurance requirements

### Research Objectives

1. **Operationalize Data Protection by Design & Default** (Article 25 UK GDPR)
2. **Map security frameworks** to GDPR compliance requirements
3. **Design layered security controls** for high-risk surveillance systems
4. **Develop incident response procedures** aligned to NIST SP 800-61 and ISO 27035
5. **Analyze real-world breach** (Oracle EBS CVE-2025-61882) to extract defensive lessons

## Chapter 1: Data Protection Compliance

### Data Protection by Design & Default (DPbD)

#### Core Principle (Article 25 UK GDPR)

Data Protection by Design and Default must be treated as an **engineering and governance requirement**, not a "compliance afterthought". For systems combining CCTV, FRT, and centralised contact tracing, DPbD must be:

- **Embedded from requirements stage** through deployment and operation
- **Maintained through a privacy-aware SDLC** with defined "gates"
- **Evidenced through testable controls** and audit artifacts

#### DPbD Implementation Framework

**Privacy-Aware Secure Development Lifecycle (SDLC)**

| Phase | DPbD Requirements | Controls | Evidence |
|-------|------------------|----------|----------|
| **Requirements** | Define purposes, lawful basis, special category processing | Purpose statements, DPIA initiation | DPIA document, legal basis assessment |
| **Design** | Defaults enforce data minimisation, purpose limitation | Camera zoning/masking, restricted FRT triggers, separated data flows | Architecture diagrams, privacy test cases |
| **Build & Test** | Privacy/security as testable requirements | RBAC with least privilege, MFA, encryption, immutable logs | Test results, security configs |
| **Operations** | Continuous monitoring, vendor assurance, change control | Access reviews, retention enforcement, anti-function creep controls | Audit logs, governance KPIs |

#### Key DPbD Mechanisms

**1. By Design (Integrate throughout processing)**
- Privacy requirements as non-functional requirements (NFRs)
- Threat modeling + privacy misuse cases
- SDLC "privacy gates" with sign-off checkpoints

**2. By Default (Only necessary data)**
- Minimal fields in tracing DB
- Least-privilege roles
- Shortest retention as baseline
- Change control for scope expansion

**3. Data Minimisation**
- Camera zoning & privacy masking
- Avoid always-on identification (use detection/counting where possible)
- Collect only essential tracing attributes

**4. Purpose Limitation & Anti-Function Creep**
- Purpose-bound access controls with use-case tags
- Query restrictions
- Approval workflow for new purposes
- Vendor contract clauses preventing secondary use

**5. Pseudonymisation & PETs**
- Tokenization/pseudonym IDs for contact tracing
- Split databases (identifiers vs. exposure events)
- Join keys protected in KMS/HSM
- Two-person rule for re-identification

**6. Transparency & User Control**
- Layered privacy notices (QR codes, signage, app notices)
- DSAR workflow
- Clear communications plan

**7. Access Limitation (Least Privilege)**
- Role-Based Access Control (RBAC)
- Multi-Factor Authentication (MFA) for privileged roles
- Privileged Access Management (PAM)
- Quarterly access reviews

**8. Integrity & Confidentiality**
- Encryption in transit/at rest
- Secure API gateway
- Network segmentation
- Endpoint Detection & Response (EDR)
- Immutable audit logs

**9. Storage Limitation**
- Automated retention enforcement
- Deletion workflows
- Cryptographic erasure for keys
- WORM logs for audit trails

**10. DPIA as Living Control**
- Completed early in lifecycle
- Reviewed on system changes
- Risk register maintained
- Mitigation tracking

### Framework Comparison Analysis

#### Overview

UK GDPR is **principles-led**, requiring organizations to demonstrate:
- Lawful, fair, transparent processing
- Purpose limitation
- Data minimisation
- Accuracy
- Storage limitation
- Integrity & confidentiality
- Accountability

Security and governance frameworks help convert GDPR's high-level obligations into actionable controls, but they **do not replace GDPR compliance**.

#### Framework Mapping to GDPR Principles

| GDPR Principle | ISO/IEC 27001 | Cyber Essentials | NIST CSF 2.0 | COBIT 2019 |
|----------------|---------------|------------------|--------------|------------|
| **Lawfulness, fairness, transparency** | Partial (governance, policies) | Limited | Partial ("Govern") | Partial (governance) |
| **Purpose limitation** | Partial (scope, change control) | Limited | Partial ("Govern/Identify") | **Strong** (prevents function creep) |
| **Data minimisation** | Partial (risk-based design) | Limited | Partial (inventory, risk controls) | Partial (enforces decisions) |
| **Accuracy** | Partial (quality management) | Limited | Partial (monitoring) | Partial (metrics, assurance) |
| **Storage limitation** | **Strong** (retention, deletion, audit) | Limited | Partial ("Protect/Recover") | Partial (KPIs, audits) |
| **Integrity & confidentiality** | **Strong** (security controls) | **Strong** (baseline) | **Strong** (Protect/Detect/Respond) | **Strong** (governance) |
| **Accountability** | **Strong** (ISMS, documentation) | Partial (evidence baseline) | **Strong** ("Govern" function) | **Strong** (decision rights, KPIs) |

#### Framework Strengths & Best Use

**ISO/IEC 27001**
- **Primary Value**: Information Security Management System (ISMS)
- **Best For**: Organizational-level security governance, risk treatment, audit readiness
- **Key Contribution**: 93 Annex A controls covering access control, cryptography, supplier security, logging, incident management
- **GDPR Support**: Strong for integrity/confidentiality, accountability, storage limitation

**Cyber Essentials**
- **Primary Value**: Baseline technical hygiene standard
- **Best For**: Protecting against common internet-based attacks
- **Key Contribution**: 5 core controls (firewalls, secure config, patching, access control, malware protection)
- **GDPR Support**: Strong for baseline security, limited for higher-order privacy obligations
- **Positioning**: "Minimum bar" within broader governance model

**NIST CSF 2.0**
- **Primary Value**: Operational security structure
- **Best For**: Day-to-day security outcomes and maturity improvements
- **Key Contribution**: 6 core functions (Govern, Identify, Protect, Detect, Respond, Recover)
- **GDPR Support**: Strong for integrity/confidentiality, "Govern" function supports accountability
- **Operational Model**: Risk management lifecycle framework

**COBIT 2019**
- **Primary Value**: Enterprise governance of IT
- **Best For**: Leadership accountability, decision rights, performance measurement
- **Key Contribution**: 40 governance/management objectives, KPIs/KRIs, assurance mechanisms
- **GDPR Support**: Strong for preventing "privacy theatre", formalizing ownership
- **Focus**: Who decides, how performance is monitored, how assurance is obtained

#### Critical GDPR Gaps Not Covered by Frameworks

| GDPR Obligation | Why Frameworks Don't Cover It | Required GDPR-Specific Controls |
|-----------------|-------------------------------|--------------------------------|
| **Lawful basis + special category conditions** | Frameworks don't determine legal basis | Document lawful basis, special category condition, alternatives/opt-out, records |
| **Necessity & proportionality** | Focus on "how to secure", not "should we do this" | Necessity assessment, strict purpose statements, approval gates, re-justification |
| **DPIA lifecycle** | Not a security standard requirement | DPIA pre-deployment, updates on change, DPO input, escalation process |
| **Transparency** | Don't specify notice content or signage | Layered privacy notices, CCTV/FRT signage, rights messaging |
| **Individual rights** | Don't define DSAR workflows | DSAR process, identity verification, retrieval/redaction, erasure handling |
| **Fairness/accuracy in FRT** | Don't require bias testing | Accuracy thresholds, bias testing, human-in-the-loop, error escalation |
| **Data minimisation by default** | Don't impose "minimum necessary" as legal default | Default minimised collection/retention/access, design constraints |
| **Breach reporting** | Cover incident response, not GDPR thresholds | Breach assessment workflow, 72-hour notification process, evidence pack |

#### Integrated Compliance Model

**Recommended Approach:**

1. **GDPR (+ DPbD)** as compliance "north star"
   - Define lawful purposes, minimisation, retention, transparency, rights

2. **ISO/IEC 27001** as assurance backbone
   - ISMS for governance, risk treatment, supplier assurance, continual improvement

3. **NIST CSF 2.0** as operational security roadmap
   - Organize security outcomes across Govern → Recover

4. **Cyber Essentials** as baseline control set
   - Address common internet-based attacks

5. **COBIT** as governance overlay
   - Leadership accountability, KPIs/KRIs, assurance mechanisms

**Key Principle**: GDPR defines **what must be protected and why**, while frameworks define **how protection is executed, measured, and evidenced**.

### Security Implementation & Incident Response

#### Layered Security Architecture

**Defense-in-Depth Model** across:
- Endpoints
- Networks
- Identities
- Applications
- Data

#### Technical Security Controls

**1. Identity & Access Management**
- Role-Based Access Control (RBAC) with least privilege
- Multi-Factor Authentication (MFA) for privileged roles
- Privileged Access Management (PAM) with session recording
- Regular access reviews

**2. Data Protection**
- Encryption in transit (TLS)
- Encryption at rest with key management
- Key Management Service (KMS) / Hardware Security Module (HSM)

**3. Network Segmentation**
- Isolated security zones:
  - Camera networks
  - FRT processing components
  - Admin consoles
  - Central tracing database
- Controlled east-west traffic
- Tightly controlled inter-zone communication

**4. System Hardening**
- Secure configuration baselines
- Vulnerability management
- Patch management
- Secure API gateways
- Third-party component security

**5. Real-Time Threat Detection**
- Centralized logging (SIEM)
- Detections for abuse cases:
  - Unusual administrative access
  - Bulk searches
  - Anomalous face-search patterns
  - Repeated failed logins
  - Unexpected data exports
  - Access outside approved hours/locations

**6. Forensic Readiness**
- Timestamped, integrity-protected logs
- Appropriate retention periods
- Chain of custody procedures
- Secure evidence storage

#### Incident Response Framework

**Aligned to NIST SP 800-61 & ISO/IEC 27035**

**Lifecycle Phases:**

1. **Preparation**
   - Defined incident categories and severity levels
   - Playbooks for common scenarios
   - Contact lists and escalation paths
   - Tools and access pre-configured

2. **Detection and Analysis**
   - SIEM alerting
   - Threat hunting
   - Incident triage and classification
   - Evidence collection

3. **Containment, Eradication, and Recovery**
   - Isolate affected systems
   - Disable compromised accounts
   - Preserve evidence
   - Root cause analysis
   - System restoration

4. **Post-Incident Activity**
   - Lessons learned
   - Process improvements
   - Control updates
   - Documentation

#### Incident Severity Classification Matrix

| Severity | Typical Triggers | Immediate Actions | Escalation | External Reporting | Timeline |
|----------|-----------------|-------------------|------------|-------------------|----------|
| **SEV 1 Critical** | Confirmed exfiltration of tracing DB/biometric templates; ransomware; active unauthorized admin access | Activate IR; isolate systems; disable accounts; preserve evidence | CISO, DPO, Legal, Senior leadership, Comms | ICO notification if personal data breach threshold met (≤72 hrs) | 0-1hr: containment; <4hrs: exec engagement; <24hrs: risk assessment |
| **SEV 2 High** | Large-scale unauthorized access; privileged credential compromise; suspected data export | Contain; rotate keys; force MFA reset; forensic triage | DPO, Legal, Business owner, Comms | Likely ICO notification depending on risk | 0-2hrs: lockdown; <8hrs: forensics; <24hrs: regulator pack |
| **SEV 3 Medium** | Malware on single endpoint; minor misconfiguration; suspicious access attempts | Fix, patch, verify logs | Security manager, DPO if data exposure possible | Usually not reportable unless threshold met | Same day: remediate; <48hrs: lessons learned |
| **SEV 4 Low** | Port scan; blocked brute-force; phishing reported; minor outage | Triage, record, tune controls | IT security if pattern repeats | No external reporting | <24hrs: close ticket; weekly/monthly trend review |
| **SEV 5 Informational** | Benign alerts, false positives | Document outcome | None unless emerging risk | None | As needed |

#### GDPR Breach Notification Requirements

**Article 33 UK GDPR**: Controller must notify supervisory authority without undue delay and, where feasible, **within 72 hours of becoming aware** of notifiable breach.

**Article 34 UK GDPR**: If breach likely to result in **high risk to individuals' rights and freedoms**, communicate to affected individuals without undue delay.

**Required Capabilities:**
- Breach log maintained
- Defined "awareness" trigger
- Rapid assessment process:
  - Scope
  - Affected data types
  - Risk to individuals
  - Containment actions
- Evidence-based reporting decisions
- Documentation of delays and rationale

## Chapter 2: Oracle EBS Breach Case Study

### CVE-2025-61882 Analysis

#### Incident Overview

**Campaign Name**: CL0P-branded extortion campaign  
**Target**: Organizations running on-premises Oracle E-Business Suite (EBS)  
**Vulnerability**: CVE-2025-61882 (Critical zero-day)  
**Attack Type**: Data theft for extortion (non-ransomware)

#### Timeline

| Date | Event |
|------|-------|
| **July-Aug 2025** | Suspicious activity observed; exploitation assessed as early as 9 Aug 2025 |
| **29 Sep 2025** | Multiple organizations receive extortion emails claiming EBS compromise |
| **Early Oct 2025** | Security vendors and national agencies issue alerts |
| **Oct 2025** | Oracle publishes security alert identifying CVE-2025-61882 |
| **Oct-Nov 2025** | CL0P leak site expands; dozens of alleged victims; significant datasets exposed |

#### Vulnerability Technical Details

**CVE-2025-61882 Characteristics:**
- **CVSS Score**: 9.8 (Critical)
- **Affected Versions**: Oracle EBS 12.2.3–12.2.14
- **Attack Vector**: Network (internet-facing)
- **Authentication**: None required (pre-auth)
- **Impact**: Remote Code Execution (RCE)
- **Affected Component**: Oracle Concurrent Processing / BI Publisher Integration

**Why This is Dangerous:**
- Pre-authentication + network reachable + RCE = catastrophic
- Enables attackers to access core business data without credentials
- Can interact with reports, documents, and data sources
- Internet-facing ERP components = high-value attack surface

#### Organizational Impact & Losses

**Primary Impact**: Confidentiality loss through mass data exfiltration

**Impact Categories:**

1. **Operational Disruption & Recovery**
   - Systems taken offline for investigation
   - Credential/key rotation
   - Baseline restoration
   - Emergency patching
   - Downtime and remediation costs

2. **Regulatory & Legal Exposure**
   - Exfiltration of personal data (employees, contractors, customers)
   - UK/EU GDPR notification obligations
   - Risk assessment and documentation requirements
   - Potential fines and legal action

3. **Direct Financial Loss**
   - Extortion demands (reported: multi-million dollar range)
   - Business impact of potential exposure
   - Operational costs

4. **Reputational Damage**
   - Public naming on CL0P leak site (~30 organizations)
   - Trust erosion
   - Follow-on risks:
     - Credential stuffing
     - Phishing using stolen documents
     - Identity/banking fraud (if payroll/HR exposed)

**Example Victim**: Korean Air's catering/duty-free unit
- Tens of thousands of employee records
- Very large data volumes allegedly leaked
- Illustrates ERP breach scale and impact

### Attacker TTPs & Defensive Countermeasures

#### Attacker Tactics, Techniques, and Procedures

**Campaign Characterization**: Data-theft extortion via mass exploitation (not traditional ransomware)

**1. Initial Access**
- **Method**: CVE-2025-61882 exploitation
- **Target**: Internet-facing Oracle EBS HTTP services
- **Scale**: Mass exploitation across multiple organizations
- **Effectiveness**: Pre-auth RCE = high-likelihood, high-impact entry

**2. Social Engineering Amplification**
- **Two-Part Operation**:
  - Part 1: Months of intrusion activity against EBS environments
  - Part 2: High-volume extortion email campaign (29 Sep 2025)
- **Tactic**: Emails sent from hundreds/thousands of compromised third-party accounts
- **Source**: Credentials likely sourced from infostealer logs
- **Goal**: Bypass spam controls, increase legitimacy, pressure victims
- **Separation**: Access operations decoupled from monetization operations

**3. Execution & Persistence**
- **Implant**: Multi-stage Java implant framework
- **Storage Location**: **EBS database itself** (not file system)
- **Specific Tables**: `XDO_TEMPLATES_B` and `XDO_LOBS`
- **Evasion Technique**: Malicious payloads appear as "application content"
- **Implication**: Patching alone insufficient; persistence may remain post-patch

**4. Discovery, Collection & Exfiltration**
- **Target Repositories**:
  - ERP documents
  - BI Publisher outputs
  - HR/finance artifacts
- **Process**: Quick identification → staging collections → exfiltration
- **Proof**: Actors provided legitimate file listings from victim environments
- **Motivation**: Enable leverage for extortion
- **Stealth**: Minimal interest in long-term stealth post-data theft

#### Why These Methods Worked

**Three Systemic Failures:**

1. **Attack Surface Exposure**
   - Public-facing EBS components
   - Single point of catastrophic failure with pre-auth RCE

2. **Patch Latency & Version Lifecycle Risk**
   - NHS England warning: "sustaining support" or EOL EBS releases no longer receive updates
   - Upgrade debt increases exploitability windows

3. **Detection Gaps**
   - No application-aware monitoring
   - Database template hunting not implemented
   - Unusual report/template creation not detected
   - Abnormal admin queries invisible

#### Defensive Countermeasures

**1. Emergency Patching + Exposure Reduction (PREVENT)**

**Actions:**
- Apply Oracle emergency patches immediately
- Remove EBS from direct internet exposure
- Implement VPN/Zero Trust access
- Deploy allowlisting
- Add WAF rules where feasible

**Framework Mapping**: ISO 27001 (change/patch governance); NIST CSF (Protect)

**Evidence**: Oracle security alert, NHS England assessment

**2. Compromise Hunting & Eradication (ASSUME BREACH)**

**Actions:**
- Hunt for malicious content in EBS database
- Check `XDO_*` table anomalies
- Look for suspicious template creation patterns
- Treat "patch applied" as **start** of incident response, not end

**Framework Mapping**: NIST CSF (Detect/Respond); ISO 27001 (logging/monitoring, incident management)

**Evidence**: Mandiant guidance on database-resident payloads

**3. Least Privilege, Segmentation & Credential Hardening (LIMIT BLAST RADIUS)**

**Actions:**
- Enforce strict RBAC for EBS administration
- Isolate EBS application tiers from broader networks
- Protect database and service accounts:
  - Rotation
  - Vaulting
  - MFA where possible
- Reduce post-exploit lateral movement

**Framework Mapping**: Cyber Essentials (access control, secure config); ISO 27001 (access control); NIST CSF (Protect)

**4. Telemetry & Detection Engineering (REDUCE DWELL TIME)**

**Actions:**
- Centralize EBS logs, database audit logs, admin activity into SIEM
- Alert on:
  - Unusual report/template creation
  - Bulk document enumeration
  - Anomalous executive-targeted themes
  - Abnormal data exports
- Application-aware detections for database-resident payloads

**Framework Mapping**: NIST CSF (Detect); COBIT (KPIs/KRIs oversight)

**5. Governance Controls for Extortion Pressure (MANAGE CRISIS)**

**Actions:**
- Executive playbooks for extortion emails
- Verification steps
- Legal/DPO escalation paths
- Communications governance
- Evidence collection procedures

**Framework Mapping**: COBIT (governance objectives); NIST CSF (Govern/Respond)

**Effectiveness**: Prevents rushed, uninformed decisions under pressure

### Risk Assessment & Mitigation Strategy

#### Risk Assessment Methodology

**Model**: Likelihood (1-5) × Impact (1-5) = Risk Score

**Risk Categories:**
- **Low**: 1–5
- **Medium**: 6–10
- **High**: 11–15
- **Critical**: 16–25

#### Risk Register

| Asset Type | Threat Scenario | Key Vulnerability | L | I | Score | Targeted Mitigation |
|------------|----------------|-------------------|---|---|-------|---------------------|
| Internet-facing Oracle EBS | Pre-auth RCE via CVE-2025-61882 | Internet exposure + patch latency | 5 | 5 | **25 Critical** | Emergency patching, remove direct exposure, WAF/allowlisting, upgrade EOL versions |
| EBS database + BI Publisher templates | Payload persistence in DB tables | Insufficient DB auditing, weak integrity monitoring | 4 | 5 | **20 Critical** | Threat hunting per Mandiant; DB audit logging; integrity checks; restrict template authoring |
| Privileged identities (admins, DBAs) | Privilege misuse for data export | Excess privilege, weak MFA/PAM, shared accounts | 4 | 5 | **20 Critical** | PAM + MFA; least privilege; break-glass controls; rotate secrets/keys |
| Sensitive data stores (HR/finance/PII) | Mass theft for extortion | Over-broad access, weak segmentation, weak DLP | 4 | 5 | **20 Critical** | Data classification; DLP; segmented access; encryption; query/export controls; bulk access monitoring |
| Network segmentation & perimeter | Pivot from EBS to internal systems | Flat network, permissive east-west traffic | 3 | 5 | **15 High** | Zero Trust access; micro-segmentation; restrict DB/admin ports; egress controls |
| Logging/SIEM & detection | Long dwell time / stealthy theft | Missing app-aware telemetry | 3 | 4 | **12 High** | Centralise EBS/DB logs; alert on anomalous template creation, bulk exports, suspicious admin activity |
| Patch & vulnerability management | Repeat exposure to future zero-days | Incomplete asset inventory, slow emergency patching | 4 | 4 | **16 Critical** | Patch SLAs by severity; asset ownership; continuous scanning; emergency change process |
| Admin endpoints / jump hosts | Credential theft → privileged access | Weak hardening, local admin rights | 3 | 4 | **12 High** | Hardened jump hosts; EDR; block credential dumping; remove local admin; device posture checks |
| Backups & recovery systems | Secondary ransomware/extortion | Untested restores, backup exposure | 3 | 4 | **12 High** | Immutable backups; offline copies; regular restore testing; separate backup credentials |
| Third parties (EBS support, hosting) | Supply-chain access or delayed patching | Unclear shared responsibilities, weak assurance | 3 | 4 | **12 High** | Contractual security clauses; patch responsibility matrix; vendor assurance reviews; audit rights |

#### Prioritised Mitigation Strategy

**Top Priority (Critical Risks)**

1. **Close Initial Access Path**
   - Apply Oracle's fix for CVE-2025-61882
   - Reduce exposure (remove direct internet access)
   - Enforce controlled access routes and filtering
   - **Rationale**: Oracle and national guidance emphasize urgent patching due to likely exploitation

2. **Assume Compromise & Eradicate Persistence**
   - Hunt for database-resident artifacts
   - Check suspicious BI Publisher template activity
   - Validate integrity of EBS content repositories
   - **Rationale**: Mandiant guidance on payload persistence in DB tables

3. **Lock Down Privilege & Stop Bulk Theft**
   - Implement PAM/MFA
   - Enforce least privilege
   - Strong separation of duties
   - Monitor abnormal export/query patterns
   - **Rationale**: Campaign value comes from rapid data exfiltration

4. **Harden Governance & Response Readiness**
   - Define emergency patch SLAs
   - Assign owners for each EBS component
   - Create executive extortion playbooks
   - **Rationale**: Evidence-led decision-making under pressure

**Secondary Priority (High Risks)**

5. **Reduce Blast Radius**
   - Segmentation and egress control
   - Limit lateral movement and data staging

6. **Improve Detection**
   - Forward EBS/DB audit signals into SIEM
   - Create tailored detections for this incident type

7. **Enhance Resilience**
   - Immutable backups
   - Tested recovery procedures
   - Reduce extortion leverage

8. **Supplier Assurance**
   - Clear contractual responsibilities
   - Auditable patch/monitoring/incident handling

#### GDPR Compliance Linkage

This risk treatment approach directly supports:

- **Integrity & Confidentiality** (Article 5(1)(f))
- **Accountability** (Article 5(2))
- **Demonstrable control strategy** for high-impact personal data processing
- **Breach readiness** for timely assessment/reporting obligations (Articles 33-34)

## Key Deliverables

### 1. DPbD Operationalization Framework

**Comprehensive table mapping:**
- DPbD requirements
- System-specific implementations (CCTV/FRT/tracing)
- Technical defaults
- Organizational controls
- Evidence/audit artifacts

### 2. Framework Comparison Matrix

**Detailed analysis of:**
- ISO/IEC 27001
- Cyber Essentials
- NIST CSF 2.0
- COBIT 2019

**Against UK GDPR principles:**
- Lawfulness, fairness, transparency
- Purpose limitation
- Data minimisation
- Accuracy
- Storage limitation
- Integrity & confidentiality
- Accountability

### 3. Integrated Compliance Model

**Recommendations for:**
- Combining GDPR as "north star"
- ISO 27001 as assurance backbone
- NIST CSF as operational roadmap
- Cyber Essentials as baseline
- COBIT as governance overlay

### 4. Incident Response Framework

**Complete lifecycle aligned to:**
- NIST SP 800-61
- ISO/IEC 27035
- UK GDPR Articles 33-34

**Including:**
- Severity classification matrix
- Escalation procedures
- Reporting timelines
- Evidence handling
- Playbooks for common scenarios

### 5. Oracle EBS Breach Analysis

**Comprehensive study covering:**
- Vulnerability technical details (CVE-2025-61882)
- Attack timeline and impact assessment
- Attacker TTPs with MITRE mapping
- Defensive countermeasures
- Risk assessment (Likelihood × Impact)
- Prioritized mitigation strategy

## Academic Context

**Module**: SEC7000 - Information Security  
**Institution**: Cardiff Metropolitan University  
**School**: Cardiff School of Technologies  
**Program**: MSc Advanced Cyber Security  
**Academic Year**: 2025/2026, Term 1  
**Module Leader**: Dr Liqaa Nawaf

### Learning Outcomes Demonstrated

1. **Data Protection by Design & Default**
   - Operationalization of Article 25 UK GDPR
   - Privacy-aware SDLC implementation
   - Technical and organizational controls

2. **Framework Integration**
   - Comparative analysis of security/governance frameworks
   - Gap identification and remediation
   - Integrated compliance modeling

3. **Security Implementation**
   - Layered defense-in-depth architecture
   - Real-time threat detection
   - Forensic readiness

4. **Incident Response**
   - Lifecycle management (NIST SP 800-61, ISO 27035)
   - Severity classification and escalation
   - GDPR breach notification procedures

5. **Real-World Application**
   - Critical analysis of Oracle EBS breach
   - Attacker TTP evaluation
   - Risk-based mitigation strategy development

### Practical Skills Development

**Immersive Labs Modules Completed:**
- Command Line Introduction
- Moving Around (Linux navigation)
- Linux File Permissions
- Cyber Million: Cyber Safety
- Cyber Million: Staying Safe Online
- Cisco Cyber Essentials labs

**Skills Gained:**
- Linux command line proficiency
- File permissions and access control
- Security risk assessment from human perspective
- User behavior as attack surface consideration
- Combining technical and user-focused controls

## References

### Primary Sources

**UK GDPR & Data Protection:**
- European Data Protection Board (EDPB) (2020) Guidelines 3/2019 on processing of personal data through video devices
- Information Commissioner's Office (ICO) - Data protection by design and default
- Information Commissioner's Office (ICO) - CCTV and video surveillance
- legislation.gov.uk - Regulation (EU) 2016/679, Article 25
- Data Protection Act 2018
- UK Government (GOV.UK) - Using CCTV

**Security Frameworks:**
- ISO/IEC 27001 - Information Security Management Systems
- NIST Cybersecurity Framework (CSF) 2.0
- NCSC Cyber Essentials Requirements (v3.1, January 2023)
- ISACA COBIT 2019

**Incident Response:**
- NIST SP 800-61 - Computer Security Incident Handling Guide
- ISO/IEC 27035-1 - Information security incident management

### Oracle EBS Breach (CVE-2025-61882)

**Threat Intelligence:**
- Google Threat Intelligence Group (GTIG) & Mandiant (2025) "Oracle E-Business Suite Zero-Day Exploited in Widespread Extortion Campaign"
- NHS England (2025) "Oracle Releases Security Advisory for E-Business Suite (CC-4705)"

**Vulnerability Databases:**
- National Vulnerability Database (NVD) - CVE-2025-61882 Detail
- Oracle Security Alert Advisory - CVE-2025-61882
- Oracle Critical Patch Update Advisory - October 2025

## Author

**Sid Ali Bendris**  
Student ID: 20238021  
MSc Advanced Cyber Security  
Cardiff Metropolitan University  
Cardiff School of Technologies

**Module Leader**: Dr Liqaa Nawaf

## License

This project is developed for academic purposes as part of the MSc Advanced Cyber Security program at Cardiff Metropolitan University.

## Acknowledgments

- Dr Liqaa Nawaf for module leadership and guidance
- Cardiff Metropolitan University for academic support
- Information Commissioner's Office (ICO) for comprehensive GDPR guidance
- Google Threat Intelligence Group and Mandiant for detailed breach analysis
- Oracle Corporation for security advisories and patch information
- NHS England Digital for national security alerts

---

**Project Status**: Completed Academic Assessment  
**Submission Date**: Term 1, Academic Year 2025/2026  
**Assessment Type**: Written Assignment (Individual)  
**Word Count**: Compliant with module requirements

**Key Themes**: Data Protection, GDPR Compliance, Biometric Surveillance, Incident Response, Risk Management, Security Frameworks, Breach Analysis
