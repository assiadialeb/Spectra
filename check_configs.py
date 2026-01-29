
import subprocess
import sys
import os

SEMGREP_PATH = '/Users/aissa/Code/Spectra/venv/bin/semgrep'

configs_to_test = [
    'p/security-audit',
    'p/secrets',
    'p/owasp-top-ten',
    'p/maintainability',
    'p/correctness',
    'p/typescript',
    'p/c',
    'p/python',
    'p/golang'
]

print(f"Testing Semgrep executable at: {SEMGREP_PATH}")

# Create dummy file
with open("test.py", "w") as f: f.write("print('hello')")

for config in configs_to_test:
    print(f"Testing config: {config} ...", end=" ", flush=True)
    cmd = [SEMGREP_PATH, 'scan', '--config', config, 'test.py', '--quiet']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 7:
            print(f"FAILED (Exit Code 7) - Invalid Config")
            print(f"STDERR: {result.stderr}")
        elif result.returncode != 0 and result.returncode != 1:
            print(f"ERROR (Exit Code {result.returncode})")
        else:
            print("OK")
    except Exception as e:
        print(f"EXCEPTION: {e}")

if os.path.exists("test.py"): os.remove("test.py")
