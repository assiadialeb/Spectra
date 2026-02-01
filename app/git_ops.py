import os
import subprocess
from flask import current_app

from app.models_settings import Settings

def clone_repository(repo_url, target_dir, depth=None):
    """
    Clones a git repository to the target directory.
    Includes logic to authenticate for private repos if PAT is configured.
    Optionally accepts a 'depth' integer for shallow cloning.
    """
    # 1. Get PAT from context or settings
    # context might be missing if running from scheduler thread without app context?
    # Usually we wrap calls in app context.
    from app.models import Settings
    
    pat = None
    try:
        settings = Settings.query.first()
        if settings and settings.github_pat:
            pat = settings.github_pat
    except:
        pass # Context issue or no DB
        
    final_url = repo_url
    if pat:
        from urllib.parse import urlsplit, urlunsplit
        try:
            parts = urlsplit(repo_url)
            # Strict Hostname Validation
            if parts.hostname and (parts.hostname == 'github.com' or parts.hostname.endswith('.github.com')):
                 if parts.scheme in ['http', 'https']:
                    new_netloc = f"{pat}@{parts.hostname}"
                    final_url = urlunsplit((parts.scheme, new_netloc, parts.path, parts.query, parts.fragment))
        except Exception as e:
            print(f"Warning: Failed to parse repository URL: {e}")
            final_url = repo_url # Fallback

    # Git Clone Command
    cmd = ['git', 'clone', final_url, target_dir]
    
    if depth:
        cmd.extend(['--depth', str(depth)])

    try:
        # Check if git is installed
        subprocess.run(['git', '--version'], check=True, stdout=subprocess.DEVNULL)
        
        # Run Clone
        # capture_output=True to hide sensitive URL in logs unless error
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to clone repository: {e}")
        return False
