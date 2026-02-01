import os
import json
import subprocess
import tempfile
import sys
import shutil
from app.git_ops import clone_repository
from collections import Counter
from pathlib import Path
from app.parsers.trivy_parser import TrivyParser
from app.parsers.semgrep_parser import SemgrepParser

# Extension Mapping for Language Detection
EXTENSION_MAP = {
    '.py': 'python',
    '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript',
    '.ts': 'typescript', '.tsx': 'typescript',
    '.php': 'php',
    '.java': 'java',
    '.go': 'go',
    '.rb': 'ruby',
    '.tf': 'terraform', '.hcl': 'terraform',
    '.c': 'c', '.cpp': 'cpp', '.h': 'c', '.hpp': 'cpp',
    '.rs': 'rust',
    '.cs': 'csharp',
    '.sh': 'bash',
    '.kt': 'kotlin',
    '.scala': 'scala',
    '.swift': 'swift',
    '.html': 'html',
    '.yml': 'yaml', '.yaml': 'yaml'
    # Dockerfile is handled separately in _detect_languages or mapped if it has no extension?
    # Actually, for file-based detection we might need to check filename if extension is empty.
    # But for now, let's keep extension map simple. 
}

# Mapping Languages to Semgrep Rulesets
LANGUAGE_RULES = {
    'python': [
        'p/python', 
        'r/python.lang.best-practice',
        'r/python.lang.correctness' 
    ],
    'javascript': [
        'p/javascript', 
        'r/javascript.lang.best-practice',
        'r/javascript.lang.correctness',
        'p/react'
    ],
    'typescript': [
        'p/typescript',
        'r/typescript.lang.best-practice',
        'r/typescript.lang.correctness',
        'p/react'
    ],
    'go': [
        'p/golang', 
        'r/go.lang.best-practice',
        'r/go.lang.correctness'
    ],
    'java': [
        'p/java', 
        'r/java.lang.best-practice',
        'r/java.lang.correctness'
    ],
    'csharp': [
        'p/csharp', 
        'r/csharp.lang.best-practice',
        'r/csharp.lang.correctness'
    ],
    'php': [
        'p/php', 
        'r/php.lang.best-practice',
        'r/php.lang.security'
    ],
    'ruby': [
        'p/ruby', 
        'r/ruby.lang.best-practice',
        'r/ruby.lang.correctness'
    ],
    'rust': [
        'p/rust', 
        'r/rust.lang.correctness'
    ],
    'terraform': [
        'p/terraform', 
        'r/terraform.lang.best-practice'
    ],
    'docker': [
        'p/dockerfile',
        'r/dockerfile.best-practice'
    ],
    'c': [
        'p/c', 
        'r/c.lang.correctness'
    ],
    'cpp': [
        'p/ci',
        'r/cpp.lang.correctness'
    ],
    'html': [
        'r/html.lang.best-practice'
    ],
    'yaml': [
        'r/yaml.lang.best-practice'
    ]
}

class ScanEngine:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.trivy_parser = TrivyParser()
        self.semgrep_parser = SemgrepParser()

    def run(self, repositories, include_secrets=True, config=None):
        """
        Orchestrates the scan process with optional configuration.
        """
        config = config or {}
        # Default Enable All if not specified
        enable_semgrep = config.get('enable_semgrep', True)
        enable_trivy = config.get('enable_trivy', True)
        # include_secrets override
        enable_gitleaks = include_secrets if include_secrets else config.get('enable_gitleaks', False)
        
        # Gitleaks / Git Clone Config
        gitleaks_mode = config.get('gitleaks_mode', 'full') # full, depth, no-git
        gitleaks_depth = config.get('gitleaks_depth', None)
        
        # Calculate Clone Depth
        clone_depth = None
        if gitleaks_mode == 'no-git':
            clone_depth = 1 # We only need files
        elif gitleaks_mode == 'depth' and gitleaks_depth:
            clone_depth = int(gitleaks_depth)

        all_vulnerabilities = []
        all_quality = []
        all_secrets = [] # Default empty
        
        # Create unique temp dir for this scan
        scan_dir = tempfile.mkdtemp(prefix=f"spectra_scan_{self.scan_id}_")
        print(f"[Scan {self.scan_id}] Workspace: {scan_dir}")
        
        try:
            # 1. Clone Repositories
            self._clone_repos(repositories, scan_dir, depth=clone_depth)
            
            # 2. Run Trivy
            if enable_trivy:
                print(f"[Scan {self.scan_id}] Running Trivy...")
                trivy_results = self._run_trivy(scan_dir)
                trivy_vulns, trivy_quality = self.trivy_parser.parse(trivy_results, self.scan_id, base_path=scan_dir)
                all_vulnerabilities.extend(trivy_vulns)
                all_quality.extend(trivy_quality)
            else:
                print(f"[Scan {self.scan_id}] Skipping Trivy (Disabled)")
            
            # 3. Run Semgrep
            if enable_semgrep:
                print(f"[Scan {self.scan_id}] Running Semgrep...")
                semgrep_results = self._run_semgrep(scan_dir)
                semgrep_vulns, semgrep_quality = self.semgrep_parser.parse(semgrep_results, self.scan_id, base_path=scan_dir)
                all_vulnerabilities.extend(semgrep_vulns)
                all_quality.extend(semgrep_quality)
            else:
                print(f"[Scan {self.scan_id}] Skipping Semgrep (Disabled)")
            
            # 4. Run Gitleaks (If enabled)
            if enable_gitleaks:
                print(f"[Scan {self.scan_id}] Running Gitleaks...")
                gitleaks_results = self._run_gitleaks(scan_dir, no_git=(gitleaks_mode == 'no-git'))
                all_secrets = self._parse_gitleaks(gitleaks_results)
            else:
                print(f"[Scan {self.scan_id}] Skipping Gitleaks (Disabled)")
            
        except Exception as e:
            print(f"[Scan {self.scan_id}] Error: {e}")
            raise e
        finally:
            # Cleanup
            print(f"[Scan {self.scan_id}] Cleaning up workspace...")
            shutil.rmtree(scan_dir, ignore_errors=True)
            
        return all_vulnerabilities, all_quality, all_secrets

    def _run_gitleaks(self, target_dir, no_git=False):
        all_leaks = []
        
        # Iterate over each cloned repository in the target_dir
        # Structure: target_dir/<repo_name>/...
        
        # Get list of subdirectories (repos)
        subdirs = [os.path.join(target_dir, d) for d in os.listdir(target_dir) if os.path.isdir(os.path.join(target_dir, d))]
        
        for repo_dir in subdirs:
            # In no_git mode, we check files even if .git is present (though clone depth 1 has .git usually)
            # Actually gitleaks --no-git treats .git as just another folder or ignores it, 
            # but mainly works on plain files.
            
            output_file = os.path.join(repo_dir, 'gitleaks_output.json')
            
            # gitleaks detect --source=repo_dir --report-format=json --report-path=output_file
            cmd = [
                'gitleaks', 'detect',
                '--source', repo_dir,
                '--report-format', 'json',
                '--report-path', output_file,
                '--no-banner',
                '--redact', # Redact secrets in output
                '--exit-code', '0', # Don't return error on leaks
                '--verbose',
            ]
            
            if no_git:
                cmd.append('--no-git')
            
            try:
                print(f"Executing Gitleaks command for {os.path.basename(repo_dir)}: {' '.join(cmd)}")
                subprocess.run(cmd, check=True, capture_output=True)
                
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        leaks = json.load(f)
                        # Enrich leak data with repo name if needed? 
                        # Or maybe just append. The path will be relative to repo_dir usually in report.
                        # Let's verify file paths later.
                        all_leaks.extend(leaks)
                        
            except subprocess.CalledProcessError as e:
                print(f"Gitleaks failed for {os.path.basename(repo_dir)}: {e.stderr.decode() if e.stderr else e}")
            except Exception as e:
                print(f"Gitleaks error: {e}")
            
        return all_leaks

    def _parse_gitleaks(self, results):
        secrets = []
        from datetime import datetime
        
        # Gitleaks JSON structure:
        # [{
        #   "Description": "Generic API Key",
        #   "StartLine": 12,
        #   "EndLine": 12,
        #   "StartColumn": 18,
        #   "EndColumn": 48,
        #   "Match": "key=...",
        #   "Secret": "...",
        #   "File": "configs/app.ini",
        #   "Commit": "...",
        #   "Entropy": 3.5,
        #   "Author": "...",
        #   "Email": "...",
        #   "Date": "2021-01-01T12:00:00Z",
        #   "Message": "..."
        # }]

        for leak in results:
            try:
                # Convert date string to datetime object
                # Format is usually ISO 8601: 2023-10-25T10:43:12Z
                leak_date = None
                if 'Date' in leak and leak.get('Date'):
                     date_str = leak.get('Date')
                     # Handle Z suffix
                     date_str = date_str.replace('Z', '+00:00')
                     try:
                        leak_date = datetime.fromisoformat(date_str)
                     except:
                        pass
                
                secret = {
                    'title': leak.get('Description', 'Unknown Secret'),
                    'match': leak.get('Secret', ''), # Using Secret field usually contains the match
                    'rule_id': leak.get('RuleID', leak.get('Description')),
                    'file_path': leak.get('File', ''),
                    'start_line': leak.get('StartLine'),
                    'end_line': leak.get('EndLine'),
                    'commit_sha': leak.get('Commit'),
                    'commit_message': leak.get('Message'),
                    'commit_date': leak_date,
                    'author': leak.get('Author'),
                    'email': leak.get('Email')
                }
                secrets.append(secret)
            except Exception as e:
                print(f"Error parsing leak: {e}")
                continue
                
        return secrets

    def _clone_repos(self, repositories, base_dir, depth=None):
        for repo in repositories:
            # Unique folder for each repo
            repo_dir = os.path.join(base_dir, repo.name)
            os.makedirs(repo_dir, exist_ok=True)
            
            success = clone_repository(repo.url, repo_dir, depth=depth)
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
        
        # 1. Detect Languages
        detected_langs = self._detect_languages(target_dir)
        print(f"[Scan {self.scan_id}] Detected languages: {', '.join(detected_langs)}")
        
        # Determine Semgrep Executable Path
        # Try to find it in the current python environment bin/
        semgrep_exec = os.path.join(sys.prefix, 'bin', 'semgrep')
        if not os.path.exists(semgrep_exec):
            # Fallback to PATH
            semgrep_exec = 'semgrep'

        # 2. Build Command
        cmd = [
            semgrep_exec, 'scan',
            '--json',
            '--output', output_file,
            
            # Base Security Rules (Always ON)
            '--config', 'p/security-audit',
            '--config', 'p/secrets',
            '--config', 'p/owasp-top-ten',
        ]
        
        # 3. Add Language Specific Rulesheets
        for lang in detected_langs:
            if lang in LANGUAGE_RULES:
                for rule_config in LANGUAGE_RULES[lang]:
                    cmd.extend(['--config', rule_config])

        # semgrep scan --json --output output_file target_dir
        cmd.extend([
            '--no-git-ignore', 
            target_dir
        ])
        
        try:
            print(f"Executing Semgrep command: {' '.join(cmd)}")
            # Capture both stdout and stderr
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    return json.load(f)
        except subprocess.CalledProcessError as e:
            print(f"Semgrep failed (Exit Code {e.returncode})")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
        except Exception as e:
            print(f"Semgrep error: {e}")
            
        return {}

    def _detect_languages(self, repo_path):
        """
        Scans the directory to find dominant languages (>5% of files).
        """
        extension_counts = Counter()
        total_files = 0
        
        for root, dirs, files in os.walk(repo_path):
            # Skip hidden folders
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules']
            
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                
                # Check for Dockerfile specifically
                if file == 'Dockerfile':
                    extension_counts['docker'] += 1
                    total_files += 1
                elif ext in EXTENSION_MAP:
                    extension_counts[EXTENSION_MAP[ext]] += 1
                    total_files += 1

        if total_files == 0:
            return []

        # Keep languages that represent > 5% of recognized files
        dominant_languages = [
            lang for lang, count in extension_counts.items() 
            if (count / total_files) > 0.05
        ]
        
        return list(set(dominant_languages))
