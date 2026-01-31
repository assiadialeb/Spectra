# Running Scans

Spectra supports two main types of security scans:

## 1. SAST (Static Analysis)
Scans your source code repositories for:
*   **Vulnerabilities** (OWASP Top 10)
*   **Secrets** (API Keys, Passwords)
*   **Code Quality** Issues

## 2. DAST (Dynamic Analysis)
Scans your running web applications for:
*   **Misconfigurations**
*   **Exposed Panels**
*   **Known CVEs**

> **Note**: DAST scans require you to configure **Target URLs** in the project settings. They are currently manual-trigger only.
