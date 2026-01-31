# Initial Configuration

Before launching your first security audit, you must configure your environment in the **Settings** tab. This setup ensures Spectra can access your private code and provide meaningful AI-driven insights.

![Settings Page](https://placehold.co/800x400?text=Spectra+Settings+Page)

## 1. General Configuration

This section defines the identity of your audit reports.

*   **Company Name**: Enter your firm's name (e.g., *Hove Security*). This name will be automatically embedded in all generated **Word (.docx)** and web reports to professionalize your deliverables.
*   **Default Language**: Choose between **English** and **French**.
    > **Note**: This setting specifically controls the internationalization of the generated reports, allowing you to present findings in your client's preferred language.

## 2. GitHub Configuration

To audit private repositories, Spectra requires a **Personal Access Token (PAT)**.

*   **PAT Requirement**: Go to your [GitHub Settings](https://github.com/settings/tokens) to generate a token with `repo` (read) access.
*   **Security First**: Your token is stored locally within your Spectra instance. It never leaves your machine and is only used to authenticate the `git clone` process.

## 3. AI Configuration (The Brain)

Spectra uses **Large Language Models (LLMs)** to analyze vulnerabilities and suggest remediations. You can choose from four major providers:

| Provider | Description | Best For |
| :--- | :--- | :--- |
| **Ollama** | Local & Private. Runs entirely on your machine. | **Maximum Sovereignty**. No data ever leaves your local environment. |
| **Google Gemini** | High-performance model with large context windows. | Detailed analysis of complex codebases. |
| **OpenAI** | Industry standard (GPT-4o, o1 support). | Precision and high-quality remediation suggestions. |
| **OpenRouter** | An aggregator giving access to diverse models (Mistral, Llama 3...). | Flexibility and cost-optimization. |

### Required Fields
*   **API Key**: Required for cloud providers (OpenAI, Gemini, OpenRouter).
*   **Model**: Specify the exact model string (e.g., `gpt-4o`, `gemini-1.5-pro`).
*   **API URL**: Mandatory for **Ollama** (usually `http://localhost:11434`) or custom local endpoints.
