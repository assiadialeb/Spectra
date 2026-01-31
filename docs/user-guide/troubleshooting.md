# Troubleshooting

If you encounter issues while using Spectra, refer to the common problems and solutions below.

## 1. Installation Issues

### Port Conflicts (Address already in use)
If you see an error like `OSError: [Errno 48] Address already in use` when starting Spectra:
*   **Cause**: Another application is using port **5001**. On macOS, the "AirPlay Receiver" feature uses port 5000 and sometimes 5001.
*   **Solution**:
    1.  Edit `run.py` or `docker-compose.yml` to use a different port (e.g., 5005).
    2.  Disable AirPlay Receiver in System Settings > General > AirDrop & Handoff.

### Docker permission denied
*   **Error**: `Got permission denied while trying to connect to the Docker daemon socket`.
*   **Solution**: Run the command with `sudo` or add your user to the docker group: `sudo usermod -aG docker $USER`.

## 2. Scan Failures

### Scan Stuck or "0 Results"
If a scan completes immediately with 0 findings, or hangs indefinitely:
1.  **Check Logs**: Spectra outputs detailed logs to the console (or Docker logs).
    ```bash
    docker-compose logs -f spectra
    ```
2.  **Authentication**: Ensure your **GitHub PAT** is valid and has `repo` scope. If the token is invalid, the `git clone` step will fail silently or show an error in the logs.
3.  **Nuclei/Trivy Missing**: If running locally (Method 1), ensure `nuclei` and `trivy` are installed in your system PATH.

## 3. AI & Reports

### "AI Provider Not Configured"
*   **Cause**: The Executive Summary in the report says "AI Provider not configured".
*   **Solution**: Go to **Settings** and ensure you have selected a provider (e.g., OpenAI) and entered a valid API Key.

### "Rate Limit Exceeded"
*   **Cause**: You are scanning a very large project, and the AI provider (OpenAI/Gemini) has blocked requests due to volume.
*   **Solution**: Wait a few minutes before regenerating the report, or switch to a provider with higher limits (or Ollama for local execution).
