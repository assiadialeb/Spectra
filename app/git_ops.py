import os
import subprocess
from flask import current_app

from app.models_settings import Settings

def clone_repository(repo_url, target_dir):
    """
    Clone a repository to a target directory.
    Supports private repositories via GITHUB_PAT (DB > Env var).
    """
    # 1. Try DB
    settings = Settings.query.first()
    pat = settings.github_pat if settings and settings.github_pat else None
    
    # 2. Fallback to Env/Config
    if not pat:
        pat = current_app.config.get('GITHUB_PAT')
    
    final_url = repo_url
    final_url = repo_url
    if pat and 'github.com' in repo_url:
        from urllib.parse import urlsplit, urlunsplit
        
        # Safe URL reconstruction
        try:
            parts = urlsplit(repo_url)
            if parts.scheme in ['http', 'https']:
                # Rebuild netloc with PAT: pat@hostname
                # parts.hostname handles cleaning up any existing auth info
                new_netloc = f"{pat}@{parts.hostname}"
                final_url = urlunsplit((parts.scheme, new_netloc, parts.path, parts.query, parts.fragment))
        except Exception as e:
            print(f"Warning: Failed to parse repository URL: {e}")
            final_url = repo_url # Fallback
        
    try:
        # Ensure target dir does not exist or clean it? 
        # For now, let git handle it or assume new unique dir per scan
        # Use partial clone to get history (for gitleaks) without all blobs (for speed).
        # We generally DO want a checkout so Semgrep/Trivy have files to scan.
        cmd = ['git', 'clone', '--filter=blob:none', final_url, target_dir]
        
        # Mask the token in logs/output
        safe_cmd_str = ' '.join(cmd).replace(pat, '***') if pat else ' '.join(cmd)
        print(f"Cloning repo: {safe_cmd_str}")
        
        subprocess.check_call(cmd)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to clone repository: {e}")
        return False
