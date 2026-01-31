# Project Management

Spectra uses a centralized project approach, allowing you to map multiple repositories and live environments to a single audit scope.

## 1. Creating a New Project

To start a new audit, navigate to the **New Project** tab. The creation process is streamlined for speed:

### Project Details

*   **Project Name**: A unique identifier for your audit (e.g., *"E-commerce Microservices"*).
*   **Description** (Optional): Brief context or scope of the project for your records.

### Audit Scope

#### Repositories (SAST)
Enter the full **HTTPS URLs** of your GitHub repositories (one per line).

> Spectra will automatically use your stored PAT to clone these for **Static Analysis**, **Dependency Scanning**, and **Secret Detection**.

#### Target URLs (DAST)
Enter the running application URLs for **Dynamic Analysis** (one per line).

> **Localhost Tip**: Use `http://host.docker.internal:[PORT]` if the target is running on your local machine and Spectra is running in Docker.

![Create Project Screen](https://placehold.co/800x600?text=Create+Project+Preview)
