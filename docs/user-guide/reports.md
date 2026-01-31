# Reports & Analysis

Once a scan is complete, Spectra provides actionable insights through two primary channels: the **Interactive Dashboard** and the **Exportable Report**.

## 1. The Interactive Dashboard

The results page serves as your immediate feedback loop. It is organized into specialized tabs to help you triage findings efficiently.

### Dashboard Overview

At the top of the report, you will find key performance indicators (KPIs):

*   **Security Grade (A-F)**: A high-level letter grade reflecting the overall security posture of the project.
    *   **F**: Critical issues found. Immediate action required.
    *   **D**: High severity issues or secrets detected.
    *   **C-B**: Medium severity issues or technical debt.
    *   **A**: No significant vulnerabilities found.
*   **Vulnerability Counters**: Quick statistics on Critical, High, and Medium findings.

### Detailed Findings Tabs

The data is segmented into specific views:

1.  **SAST (Static Analysis)**: Inspects source code patterns.
    *   Grouped by vulnerability type (OWASP Top 10).
    *   Includes a "View Fix" button to see recommended remediation steps.
2.  **DAST (Dynamic Analysis)**: Results from the live web scan (Nuclei).
    *   Shows runtime vulnerabilities like XSS or Misconfigurations.
    *   Links directly to the affected URL/Endpoint.
3.  **Secrets**: Hardcoded credentials detected in the git history.
    *   Shows the commit SHA, author, and specific file path.
    *   Provides instructions on how to rewrite git history to remove the leak.
4.  **Quality**: Code smells and maintenance issues (non-security bugs).

## 2. Exporting Reports

For compliance, auditing, or executive presentations, Spectra generates a comprehensive **Word (.docx)** report.

To generate it, click the **"Export Report"** button located in the SAST tab action bar.

### Report Structure

The generated document (`#SC-[ID] - Report.docx`) is professionally formatted and includes:

1.  **Executive Summary**: An AI-generated narrative summarizing the risk level, key findings, and strategic recommendations for non-technical stakeholders (CISO/CTO).
2.  **Scope & Methodology**:
    *   Lists all audited repositories and URLs.
    *   Details the tools used (Semgrep, Trivy, Nuclei) and the standards applied (OWASP Top 10, CWE).
3.  **Detailed Risk Analysis**:
    *   Deep-dive analysis of **CRITICAL** and **HIGH** severity issues.
    *   Each finding includes an AI-explained impact analysis and grouped locations.
4.  **Technical Inventory**: A complete, tabular list of every single finding (including Low/Info) for remediation teams.
5.  **Conclusion**: A final wrap-up and suggested roadmap.

### Localization

The report language (English/French) and the "Company Name" in the footer are determined by your **Global Settings**.
