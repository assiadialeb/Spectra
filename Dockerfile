FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=run.py \
    FLASK_DEBUG=0 \
    # Add local bin to PATH for the non-root user
    PATH="/home/spectra/.local/bin:${PATH}"

# Install system dependencies
# git: required for cloning repositories
# curl, unzip: required for installing tools
RUN apt-get update && apt-get install -y \
    git \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# --- Install Security Tools ---

# 1. Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# 2. Install Gitleaks
ENV GITLEAKS_VERSION=8.18.1
RUN curl -sSLO https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_amd64.tar.gz && \
    tar -xzf gitleaks_${GITLEAKS_VERSION}_linux_amd64.tar.gz -C /usr/local/bin gitleaks && \
    rm gitleaks_${GITLEAKS_VERSION}_linux_amd64.tar.gz && \
    chmod +x /usr/local/bin/gitleaks

# 3. Install Nuclei
ENV NUCLEI_VERSION=3.2.0
RUN curl -sSLO https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip && \
    unzip nuclei_${NUCLEI_VERSION}_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei_${NUCLEI_VERSION}_linux_amd64.zip && \
    chmod +x /usr/local/bin/nuclei

# --- Setup Non-Root User ---

# Create a non-root user 'spectra'
RUN groupadd -r spectra && useradd -r -g spectra -m -d /home/spectra spectra

# Set working directory
WORKDIR /app

# Copy requirements first (leverage cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code with ownership
COPY --chown=spectra:spectra . .

# Create instance directory ensuring permissions
RUN mkdir -p instance && chown -R spectra:spectra instance

# Switch to non-root user
USER spectra

# Expose port 5001
EXPOSE 5001

# Run the application on port 5001
CMD ["flask", "run", "--host=0.0.0.0", "--port=5001"]
