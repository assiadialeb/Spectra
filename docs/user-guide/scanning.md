# Running Your First Audit

Once your project is created, you will be redirected to the Project Dashboard. From here, you can orchestrate your security analysis.

## 1. Initiating the Scan

To start an analysis, click the **Run New Audit** button at the top right of your project page. A modal will appear, offering two distinct types of security analysis:

![Scan Selection Modal](https://placehold.co/800x400?text=Scan+Selection+Modal)

### A. Static Code Analysis (SAST)

This module inspects your source code repositories without executing them. It combines multiple engines:

*   **Semgrep**: Checks for vulnerability patterns (OWASP Top 10) and code quality issues.
*   **Trivy**: Identifies vulnerable dependencies (SCA) and infrastructure misconfigurations (IaC).
*   **Gitleaks** (Secrets Detection): Scans for hardcoded credentials and API keys.

!!! warning "Important Note on Secrets"
    You can toggle the **"Include Secrets Scan"** switch. Be aware that scanning the full Git history is a deep and resource-intensive process.
    Depending on the project's age and commit volume, this can take **several minutes to hours**. Use this for initial audits or deep compliance checks, but perhaps not for every quick iteration.

### B. Dynamic Web Analysis (DAST)

This module performs a "black-box" audit on your running applications using **Nuclei**. It checks for runtime vulnerabilities such as XSS, SQL Injections, and server misconfigurations.

*   **Target Selection**: Spectra automatically lists the URLs you configured during project creation (see *Target URLs*).
*   **Duration**: Similar to secret scanning, a DAST audit's duration depends on the size and complexity of the web application. A deep crawl of a large site will take significantly longer than a simple landing page scan.

## 2. Monitoring Progress

After launching an audit, you can track its status in the **Scan History** table at the bottom of the dashboard:

*   **Status**: Look for the <span style="color:blue">**RUNNING**</span> badge.
*   **Real-time Feedback**: You will see findings (Critical/High counts) and Secret counts update as the engines report back.
*   **Action Icons**:
    *   <span style="font-size:1.2em">👁️</span> **View**: Dive into the detailed findings report.
    *   <span style="font-size:1.2em">🗑️</span> **Delete**: Clear old scan data.

!!! info "Technical Note: Asynchronous Execution"
    All scans are executed **asynchronously** in the background. You can navigate away from the dashboard and proceed with other tasks; Spectra will continue working. The page does not need to remain open.
