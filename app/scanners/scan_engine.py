import os
import json
import subprocess
import tempfile
import shutil
from app.git_ops import clone_repository
from app.parsers.trivy_parser import TrivyParser
from app.parsers.semgrep_parser import SemgrepParser

class ScanEngine:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.trivy_parser = TrivyParser()
        self.semgrep_parser = SemgrepParser()

    def run(self, repositories):
        """
        Orchestrates the scan process:
        1. Create temp workspace
        2. Clone repos
        3. Run scanners
        4. Parse results
        5. Cleanup
        """
        all_vulnerabilities = []
        
        # Create unique temp dir for this scan
        scan_dir = tempfile.mkdtemp(prefix=f"spectra_scan_{self.scan_id}_")
        print(f"[Scan {self.scan_id}] Workspace: {scan_dir}")
        
        try:
            # 1. Clone Repositories
            self._clone_repos(repositories, scan_dir)
            
            # 2. Run Trivy
            print(f"[Scan {self.scan_id}] Running Trivy...")
            trivy_results = self._run_trivy(scan_dir)
            all_vulnerabilities.extend(
                self.trivy_parser.parse(trivy_results, self.scan_id, base_path=scan_dir)
            )
            
            # 3. Run Semgrep
            print(f"[Scan {self.scan_id}] Running Semgrep...")
            semgrep_results = self._run_semgrep(scan_dir)
            all_vulnerabilities.extend(
                self.semgrep_parser.parse(semgrep_results, self.scan_id, base_path=scan_dir)
            )
            
        except Exception as e:
            print(f"[Scan {self.scan_id}] Error: {e}")
            raise e
        finally:
            # Cleanup
            print(f"[Scan {self.scan_id}] Cleaning up workspace...")
            shutil.rmtree(scan_dir, ignore_errors=True)
            
        return all_vulnerabilities

    def _clone_repos(self, repositories, base_dir):
        for repo in repositories:
            # Unique folder for each repo
            repo_dir = os.path.join(base_dir, repo.name)
            os.makedirs(repo_dir, exist_ok=True)
            
            success = clone_repository(repo.url, repo_dir)
            if not success:
                print(f"Skipping scan for {repo.name} due to clone failure.")

    def _run_trivy(self, target_dir):
        output_file = os.path.join(target_dir, 'trivy_output.json')
        # trivy fs --format json --output output_file target_dir
        cmd = [
            'trivy', 'fs',
            '--format', 'json',
            '--output', output_file,
            '--no-progress',
            '--scanners', 'vuln,misconfig,secret', # Enable desired scanners
            target_dir
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    return json.load(f)
        except subprocess.CalledProcessError as e:
            print(f"Trivy failed: {e.stderr.decode()}")
        except Exception as e:
            print(f"Trivy error: {e}")
            
        return {}

    def _run_semgrep(self, target_dir):
        output_file = os.path.join(target_dir, 'semgrep_output.json')
        # semgrep scan --json --output output_file target_dir
        cmd = [
            'semgrep', 'scan',
            '--json',
            '--output', output_file,
            '--config', 'auto', # Use default rule registry
            '--no-git-ignore', # Important: scan everything in the temp dir, don't rely on git tracking if .git missing
            target_dir
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    return json.load(f)
        except subprocess.CalledProcessError as e:
            print(f"Semgrep failed: {e.stderr.decode()}")
        except Exception as e:
            print(f"Semgrep error: {e}")
            
        return {}
