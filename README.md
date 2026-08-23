
<p align="center">
  <img src="https://github.com/Guptaharshal1515/DigiEye/main/Images/logo.png" width="300" alt="DigiEye Logo">
</p>


# DigiEye

### Autonomous AI-Powered Cybersecurity Code Reasoning & Remediation Platform

> **DigiEye** is a defensive-by-design cyber-reasoning system that combines local AI, static analysis, dynamic analysis, fuzzing, automated patch generation, regression testing, and evidence-driven reporting to discover, understand, remediate, and verify software vulnerabilities.

---

## Overview

Modern application security produces large volumes of findings from different security scanners, but identifying the real vulnerability, understanding its context, applying a safe fix, and proving that the fix actually works still requires significant human effort.

**DigiEye** is designed to close this gap.

It acts as an autonomous security engineering system for source code and applications:

```text
Target Application
       |
       v
Scope & Environment Analysis
       |
       v
Security Analysis
  +----+---------+
  |    |         |
 SAST DAST     Fuzzing
  |    |         |
  +----+---------+
       |
       v
Finding Normalization
       |
       v
Evidence Engine
       |
       v
AI Security Reasoning
       |
       v
Risk & Root-Cause Analysis
       |
       v
Patch Generation
       |
       v
Patch Application
       |
       v
Verification & Regression Testing
       |
       +---- Fix Failed ----> Re-analysis
       |
       v
Security Evidence Package
       |
       v
Final Report
```

The core principle is:

> **A vulnerability should not be considered resolved until the system can produce evidence that the fix works.**

---

# Core Objectives

DigiEye is designed to:

- Discover vulnerabilities automatically
- Correlate findings from multiple security tools
- Reduce duplicate and noisy findings
- Preserve raw security evidence
- Understand vulnerability context using AI
- Determine root cause and security impact
- Generate remediation patches
- Apply patches in a controlled environment
- Re-run security analysis after remediation
- Perform regression testing
- Verify that the vulnerability is no longer present
- Produce machine-readable and human-readable evidence
- Maintain a complete audit trail

---

# Design Philosophy

## 1. Evidence Before Reasoning

AI should not invent vulnerabilities.

DigiEye treats scanner output, source-code locations, execution results, test results, and patch verification as evidence.

The AI reasoning layer operates on collected evidence rather than acting as the sole vulnerability detector.

## 2. Deterministic Tools + AI Reasoning

```text
Deterministic Security Tools
          +
Structured Evidence
          +
AI Reasoning
          =
Autonomous Security Workflow
```

Security scanners provide measurable technical observations while the AI provides contextual reasoning, prioritization, remediation planning, and decision-making.

## 3. Verify, Don't Assume

A generated patch is not automatically considered successful.

DigiEye verifies remediation by:

1. Re-running relevant security scanners
2. Comparing original and patched findings
3. Running regression tests
4. Performing dynamic validation where applicable
5. Checking for newly introduced security issues
6. Recording verification evidence

---

# Final Architecture

<p align="center">
  <img src="https://github.com/Guptaharshal1515/DigiEye/main/Images/Architecture.png" width="100%" alt="DigiEye Architecture">
</p>

---

# Major Components

## 1. Scope & Environment Analyzer

Determines what is being analyzed:

- Target directory
- Programming language
- Source files
- Framework
- Dependencies
- Build system
- Runtime environment
- Application entry points
- Test configuration
- Available security tools

Its purpose is to keep analysis within the requested scope.

---

# 2. SAST Engine

### Static Application Security Testing

SAST analyzes source code without executing the application.

Potential engines include:

- Semgrep
- Bandit
- CodeQL
- Flawfinder
- SonarQube
- Language-specific security analyzers

Workflow:

```text
Source Code
     |
     v
SAST Scanner
     |
     v
Raw Findings
     |
     v
Finding Normalization
```

SAST can detect:

- Injection vulnerabilities
- Unsafe API usage
- Security misconfiguration
- Hardcoded secrets
- Dangerous function calls
- Authentication/authorization weaknesses
- Insecure cryptographic usage
- Path traversal
- Command execution risks

---

# 3. DAST Engine

### Dynamic Application Security Testing

DAST analyzes a running application from the outside inside a controlled environment.

Potential tools include:

- OWASP ZAP
- Nuclei
- HTTPX
- cURL
- Wapiti
- Custom HTTP security probes

Workflow:

```text
Application
     |
     v
Discovery
     |
     v
Endpoint Analysis
     |
     v
Security Testing
     |
     v
Runtime Evidence
```

DAST can identify:

- Authentication problems
- Authorization failures
- Security headers
- Exposed endpoints
- Injection behavior
- Misconfigurations
- Runtime vulnerabilities

---

# 4. Fuzzing Engine

Fuzzing generates or mutates inputs to discover unexpected application behavior.

Potential capabilities:

- AFL++
- libFuzzer
- Python fuzzing frameworks
- HTTP fuzzing
- File-format fuzzing
- Protocol fuzzing
- Mutation-based fuzzing
- Coverage-guided fuzzing

Workflow:

```text
Input Corpus
     |
     v
Mutation / Generation
     |
     v
Application
     |
     v
Crash / Exception / Timeout
     |
     v
Minimization
     |
     v
Evidence
```

---

# 5. Finding Normalization Engine

Different scanners can report the same vulnerability.

Example:

```text
Semgrep
  -> Security Misconfiguration
     app.py:48

Bandit
  -> B104
     app.py:48
```

The normalization engine converts heterogeneous scanner output into a common schema and performs:

- Schema normalization
- Deduplication
- Finding correlation
- Severity reconciliation
- CWE/OWASP mapping
- Source tracking
- Fingerprint generation

Example:

```json
{
  "finding_id": "F-001",
  "type": "Security Misconfiguration",
  "severity": "high",
  "file": "app.py",
  "line": 48,
  "cwe": "CWE-668",
  "tools": ["semgrep", "bandit"],
  "evidence": [],
  "status": "open"
}
```

---

# 6. Evidence Engine

The Evidence Engine answers:

> **Why does DigiEye believe this vulnerability exists?**

Instead of storing only an AI-generated explanation, DigiEye maintains evidence from multiple sources.

<p align="center">
  <img src="https://github.com/Guptaharshal1515/DigiEye/main/Images/Evidence%20engine.png" width="900" alt="DigiEye Evidence Engine">
</p>

Example:

```json
{
  "finding_id": "F-001",
  "location": {
    "file": "app.py",
    "line": 48
  },
  "source_evidence": {
    "code": "app.run(host="0.0.0.0", port=8000)"
  },
  "tool_evidence": [
    {
      "tool": "Semgrep",
      "rule": "security-audit"
    },
    {
      "tool": "Bandit",
      "rule": "B104"
    }
  ],
  "runtime_evidence": [],
  "confidence": 0.95
}
```

This creates an auditable chain:

```text
Finding
   |
   v
Evidence
   |
   v
Reasoning
   |
   v
Patch
   |
   v
Verification
```

---

# 7. AI Security Reasoning Engine

The AI layer reasons over collected evidence.

It can:

- Understand the vulnerability
- Correlate multiple findings
- Determine root cause
- Estimate impact
- Prioritize vulnerabilities
- Explain exploitation conditions
- Recommend remediation
- Generate a patch strategy
- Determine what should be tested after patching

The AI should not fabricate scanner results.

Its reasoning must remain grounded in collected evidence.

---

# 8. Remediation & Patch Engine

The Patch Engine converts remediation into an actual code change.

```text
Finding
   |
   v
Root Cause
   |
   v
Remediation Strategy
   |
   v
Patch Generation
   |
   v
Safety Validation
   |
   v
Patch Application
```

Important properties:

- Create a backup/checkpoint
- Modify only authorized files
- Preserve unrelated code
- Generate machine-readable diffs
- Record before/after state
- Support rollback
- Reject unsafe or ambiguous modifications

Example:

```diff
- app.run(host="0.0.0.0", port=8000)
+ app.run(host="127.0.0.1", port=8000)
```

The patch becomes part of the evidence package.

---

# 9. Verification Engine

A patch is not considered successful simply because source code changed.

The Verification Engine checks whether the vulnerability has actually been resolved.

```text
Patched Application
        |
        +-- SAST Re-scan
        |
        +-- DAST Re-test
        |
        +-- Regression Tests
        |
        +-- Fuzzing
        |
        +-- Build / Runtime Validation
                |
                v
         Verification Result
```

Possible states:

```text
VERIFIED
PARTIALLY_VERIFIED
FAILED
INCONCLUSIVE
```

---

# 10. Regression Test Harness

Security patches can introduce functional problems.

DigiEye executes regression tests after remediation.

Testing can include:

- Unit tests
- Integration tests
- Existing project tests
- Security regression tests
- Build validation
- Application startup checks
- Custom vulnerability-specific tests

A successful security fix should ideally satisfy:

```text
Vulnerability Fixed
        AND
Regression Tests Pass
        AND
Application Still Works
```

---

# 11. Autonomous Feedback Loop

DigiEye is designed as a closed-loop security system.

```text
Discover
   |
   v
Analyze
   |
   v
Reason
   |
   v
Patch
   |
   v
Test
   |
   v
Verify
   |
   +---- PASS ----> Report
   |
   +---- FAIL
           |
           v
       Re-analyze
           |
           v
        New Patch
```

---

# 12. Reporting & Evidence Package

Every assessment produces structured artifacts.

### JSON

Machine-readable assessment containing:

- Target
- Findings
- Severity
- Evidence
- Tool sources
- Patch information
- Verification results
- Confidence
- Errors
- Warnings
- Timestamps

### PDF

Human-readable report containing:

- Executive summary
- Risk overview
- Vulnerability details
- Evidence
- Remediation
- Patch status
- Verification status
- Technical appendix

---

# Complete Security Workflow

```text
1. Receive Target
       |
2. Validate Scope
       |
3. Inspect Environment
       |
4. Identify Technology
       |
5. Run SAST
       |
6. Run DAST
       |
7. Run Fuzzing
       |
8. Normalize Findings
       |
9. Correlate Evidence
       |
10. AI Security Reasoning
       |
11. Determine Root Cause
       |
12. Generate Remediation
       |
13. Create Patch
       |
14. Apply Patch Safely
       |
15. Re-run Security Tests
       |
16. Run Regression Tests
       |
17. Verify Fix
       |
18. Generate Evidence Package
       |
19. Generate Final Report
```

---

# Technology Stack

## AI / Reasoning

- Local Large Language Models
- Qwen-class instruction models
- Ollama
- Python
- Structured tool calling
- JSON-based reasoning contracts

## Static Analysis

- Semgrep
- Bandit
- CodeQL
- Flawfinder
- SonarQube

## Dynamic Analysis

- OWASP ZAP
- Nuclei
- HTTPX
- cURL
- Wapiti

## Fuzzing

- AFL++
- libFuzzer
- Python fuzzing frameworks
- HTTP fuzzing
- Custom mutation engines

## Testing

- Pytest
- Unit testing frameworks
- Integration testing
- Security regression tests

## Reporting

- JSON
- PDF
- Structured evidence schemas

## Runtime

- Python
- Linux
- Windows
- Isolated testing environments
- Containerized execution where required

---

# Security & Safety Model

DigiEye is designed for authorized defensive security testing.

The platform incorporates:

- Explicit target scope
- Controlled execution
- Tool allowlists
- Evidence-based decisions
- Patch checkpoints
- Rollback support
- Audit logging
- Sandboxed execution
- No unsupported vulnerability claims
- Verification before marking a vulnerability resolved

---

# Example Assessment

For a vulnerable Python application:

```text
Application
    |
    +-- Semgrep ----+
    |               |
    +-- Bandit -----+--> Correlation --> Evidence
                                    |
                                    v
                              AI Reasoning
                                    |
                                    v
                              Patch Proposal
                                    |
                                    v
                              Patch Applied
                                    |
                                    v
                         Semgrep + Bandit
                                    |
                                    v
                           Regression Tests
                                    |
                                    v
                                VERIFIED
```

---

# Project Deliverables

The complete DigiEye platform provides:

### 1. Autonomous Security Agent
An AI-driven security reasoning system capable of orchestrating analysis and remediation.

### 2. Multi-Engine Security Analysis
Integration of SAST, DAST and fuzzing capabilities.

### 3. Evidence Engine
A structured evidence layer preserving the basis for security decisions.

### 4. Finding Correlation
Deduplication and normalization across multiple security tools.

### 5. Automated Remediation
AI-assisted patch generation and controlled patch application.

### 6. Verification
Automated re-analysis and regression testing.

### 7. Reporting
Machine-readable JSON and human-readable PDF reports.

### 8. Auditability

```text
Vulnerability
    |
    v
Evidence
    |
    v
Reasoning
    |
    v
Patch
    |
    v
Verification
    |
    v
Final Report
```

---

# Performance Goals

| Objective | Goal |
|---|---|
| Detection | High-precision vulnerability identification |
| Correlation | Minimize duplicate findings |
| Evidence | Preserve source and tool evidence |
| Reasoning | Evidence-grounded AI decisions |
| Remediation | Generate safe, minimal patches |
| Verification | Prove remediation through re-testing |
| Regression | Avoid breaking existing functionality |
| Reporting | Produce complete security evidence |
| Scalability | Support multiple analysis engines |
| Deployment | Support local and isolated environments |

---

# Why DigiEye?

Traditional security tooling generally follows:

```text
Scan -> Findings -> Human
```

DigiEye aims for:

```text
Scan
  |
Understand
  |
Correlate
  |
Prove
  |
Patch
  |
Test
  |
Verify
  |
Report
```

The key difference is the **closed remediation loop**.

DigiEye is not intended to replace security tools. It connects them into an autonomous security engineering workflow where important decisions are backed by evidence.

---

# Repository Structure

```text
digieye/
|
+-- agents/
|   +-- code/
|   +-- dast/
|   +-- fuzz/
|
+-- engines/
|   +-- normalization/
|   +-- evidence/
|   +-- remediation/
|   +-- verification/
|   +-- regression/
|
+-- tools/
|   +-- sast/
|   +-- dast/
|   +-- fuzzing/
|
+-- models/
+-- schemas/
+-- reports/
+-- tests/
+-- configs/
+-- docs/
|
+-- requirements.txt
+-- LICENSE
+-- README.md
```


# Research Direction

DigiEye explores the intersection of:

- Artificial Intelligence
- Cybersecurity
- Secure Software Engineering
- Automated Vulnerability Management
- Program Analysis
- Fuzzing
- Software Verification
- Autonomous Security Operations

The long-term objective is to move vulnerability management from a **detection-only workflow** toward an **evidence-driven autonomous remediation workflow**.

---

# Responsible Use

DigiEye is intended for:

- Authorized security assessments
- Defensive cybersecurity research
- Secure software development
- Vulnerability research
- Controlled testing environments
- Security education
- Cybersecurity competitions

Only analyze systems and applications for which you have explicit authorization.

---

# License

This project is intended for research, educational, and authorized defensive security purposes.

See the repository license for applicable terms.

---

## DigiEye

**Detect. Reason. Patch. Verify.**

> **A vulnerability is not resolved when a scanner stops reporting it.  
> It is resolved when the fix is supported by evidence.**
