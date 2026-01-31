FROM python:3.12-slim

# Install system dependencies
# git: required for cloning repositories
# curl: required for installing trivy
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Gitleaks
# Fetching the latest release or a pinned version is best. Pinning for stability.
ENV GITLEAKS_VERSION=8.18.1
RUN curl -sSLO https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_amd64.tar.gz && \
    tar -xzf gitleaks_${GITLEAKS_VERSION}_linux_amd64.tar.gz -C /usr/local/bin gitleaks && \
    rm gitleaks_${GITLEAKS_VERSION}_linux_amd64.tar.gz && \
    chmod +x /usr/local/bin/gitleaks

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
# We copy this first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create instance directory for SQLite
RUN mkdir -p instance

# Set environment variables
ENV FLASK_APP=run.py
ENV FLASK_DEBUG=1
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 5000

# Run the application
CMD ["flask", "run", "--host=0.0.0.0"]
