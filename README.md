# Spectra - Security Audit Platform

Spectra is an automated security audit platform designed to streamline the vulnerability assessment process for modern applications. By combining industry-leading scanning engines with AI-powered reporting, Spectra turns technical findings into actionable, professional security insights.

## 🚀 Features

*   **Multi-Engine Scanning**:
    *   **SAST (Static Application Security Testing)**: Powered by **Semgrep** for code quality and security flaws.
    *   **SCA & IaC (Supply Chain & Infrastructure)**: Powered by **Trivy** (Aqua Security) for dependencies and configuration auditing.
*   **AI-Enhanced Reporting**:
    *   Generates professional Word (.docx) reports.
    *   Includes Executive Summaries, Technical Details, and Action Plans.
    *   Supports multiple AI providers: **OpenAI**, **Google Gemini**, **Ollama**, **OpenRouter**.
*   **User-Friendly Interface**: Dashboard for project management, scan history, and configuration.
*   **Private Repositories**: Securely clone and scan private GitHub repositories using PAT authentication to a temporary isolated environment.

---

## 🛠️ Installation

### Option 1: Using Docker (Recommended)

The easiest way to run Spectra is using Docker, as it handles all external dependencies (Git, Trivy, Semgrep).

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/assiadialeb/Spectra.git
    cd spectra
    ```

2.  **Create configuration file**:
    Copy the example environment file (optional, or use UI later):
    ```bash
    cp .env.example .env
    ```

3.  **Start the container**:
    ```bash
    docker-compose up --build
    ```

4.  **Access the application**:
    Open your browser at [http://localhost:5001](http://localhost:5001).

    > **Note:** The application uses port **5001** instead of the Flask default (5000) because port 5000 is frequently reserved by the AirPlay Receiver service on macOS.

---

### Option 2: From Source (Local Development)

#### Prerequisites
*   Python 3.12+
*   Git
*   **Trivy** (Must be installed and in your PATH). [Installation Guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)
*   **Gitleaks** (Must be installed and in your PATH). [Installation Guide](https://github.com/gitleaks/gitleaks)

#### Steps

1.  **Clone and Setup Environment**:
    ```bash
    git clone https://github.com/assiadialeb/Spectra.git
    cd spectra
    python3 -m venv venv
    source venv/bin/activate
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Initialize Database**:
    The SQLite database created automatically in `instance/spectra.db` upon first run.

4.  **Run the Application**:
    ```bash
    python run.py
    ```

---

## ⚙️ Configuration

Once the application is running, navigate to the **Settings** page to configure:

1.  **General**: Company Name (for reports) and default language.
2.  **GitHub**: Provide a Personal Access Token (PAT) to allow cloning of private repositories.
3.  **AI Provider**: Choose your preferred AI backend (Gemini, OpenAI, etc.) and provide the API Key to enable the Report Generation feature.

## 🔒 Security Note

*   **Data Persistence**: Scanned code is cloned into ephemeral temporary directories (`/tmp`) and is **deleted immediately** after analysis. It is never stored permanently.
*   **Database**: Scan results and metadata are stored locally in a SQLite database (`instance/spectra.db`). Ensure this file is backed up.

## 📄 License

Spectra is released under AGPL-3.0 license.


## Credits & Acknowledgments ❤️

Spectra is proudly built upon the incredible work of the Open Source security community. We effectively stand on the shoulders of giants. Special thanks to:

*   **[Semgrep](https://semgrep.dev/)** (by Semgrep Inc.) for their revolutionary static analysis engine.
*   **[Trivy](https://aquasecurity.github.io/trivy/)** (by Aqua Security) for the most comprehensive container & filesystem scanner.
*   **[Nuclei](https://projectdiscovery.io/nuclei)** (by ProjectDiscovery) for the powerful dynamic scanner.
*   **[Gitleaks](https://github.com/zricethezav/gitleaks)** (by Zachary Rice) for keeping our secrets safe.

### Special Thanks to the Tech Stack 🛠️

We extend our deepest gratitude to the creators and maintainers of the technologies that power Spectra. Big thanks to them for their amazing work:

*   **Python, Flask, SQLAlchemy, APScheduler**: For providing the robust backend foundation.
*   **Ollama & Others LLM providersi**: For the cutting-edge intelligence APIs.
*   **python-docx**: For making complex report generation seamless.
*   **MkDocs & Material for MkDocs**: For this beautiful and easy-to-use documentation system.
*   **Bootstrap 5**: For the responsive and modern UI components.

And a massive **THANK YOU** to the countless contributors of the global Open Source ecosystem!

