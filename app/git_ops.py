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
    if pat and 'github.com' in repo_url and 'https://' in repo_url:
        # Inject PAT into URL: https://PAT@github.com/org/repo.git
        final_url = repo_url.replace('https://', f'https://{pat}@')
        
    try:
        # Ensure target dir does not exist or clean it? 
        # For now, let git handle it or assume new unique dir per scan
        cmd = ['git', 'clone', '--depth', '1', final_url, target_dir]
        
        # Mask the token in logs/output
        safe_cmd_str = ' '.join(cmd).replace(pat, '***') if pat else ' '.join(cmd)
        print(f"Cloning repo: {safe_cmd_str}")
        
        subprocess.check_call(cmd)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to clone repository: {e}")
        return False
