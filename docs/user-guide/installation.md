# Installation Guide

Spectra is a Python Flask application that can be run locally or deployed via Docker on a server.

## Method 1: Local Installation

### Prerequisites

*   **Python 3.9+**
*   **Git**
*   **Nuclei** (DAST) - [Install Guide](https://projectdiscovery.io/nuclei)
*   **Trivy** (SCA/Container) - [Install Guide](https://aquasecurity.github.io/trivy/v0.18.3/installation/)
*   **Semgrep** (SAST) - `pip install semgrep`

### Step-by-Step

#### 1. Clone the Repository

```bash
git clone https://github.com/assiadialeb/Spectra.git
cd Spectra
```

#### 2. Set up Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 4. Configuration

Create a `.env` file in the root directory:

```bash
cp .env.example .env
```

Ensure you configure the following keys:
*   `DATABASE_URL`: Your SQLite or PostgreSQL connection string.
*   `GITHUB_PAT`: Your GitHub Personal Access Token (for private repos).
*   `OPENAI_API_KEY`: For AI-generated reports.

#### 5. Run the Application

```bash
# Run on port 5001 (MacOS AirPlay conflict)
flask run --port=5001
```

Access the dashboard at `http://localhost:5001`.

---

## Method 2: Docker Installation (Recommended)

This is the easiest way to run Spectra as it bundles all dependencies (Nuclei, Semgrep, Trivy) in a container.

### Prerequisites

*   **Docker Desktop** (or Docker Engine + Compose) installed on your machine.

### Step-by-Step

#### 1. Clone the Configuration

```bash
git clone https://github.com/assiadialeb/Spectra.git
cd Spectra
```

#### 2. Configuration

Create and configure your `.env` file (same as Method 1):

```bash
cp .env.example .env
# Edit .env and add your API keys (GITHUB_PAT, OPENAI_API_KEY)
```

#### 3. Run with Docker Compose

```bash
docker-compose up -d --build
```

Spectra will build the image and start the service on port **5001**.
Access the dashboard at `http://localhost:5001`.

#### 4. Updates

To update Spectra to the latest version:

```bash
git pull
docker-compose up -d --build
```
