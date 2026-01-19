import ast
import re
import os
from pathlib import Path
from typing import List, Dict

class SourceScanner:
    # Regex patterns for finding suspicious strings in any file
    SUSPICIOUS_PATTERNS = [
        # (r"base64\.b64decode", "Base64 decoding"), # Too noisy, AST handles exec(decode)
        (r"eval\(", "Use of eval() (possible code execution)"),
        (r"subprocess\.call", "Process execution"),
        (r"subprocess\.Popen", "Process execution"),
        (r"os\.system", "Shell execution"),
        (r"socket\.socket", "Socket creation (possible C2 connection)"),
        (r"urlopen\(", "Network request (urllib)"),
        (r"requests\.get", "Network request (requests)"),
        (r"curl\s+", "Curl usage in shell/script"),
        (r"wget\s+", "Wget usage in shell/script"),
        (r"/etc/shadow", "Accessing sensitive file (/etc/shadow)"),
        (r"\.ssh/id_rsa", "Accessing SSH keys"),
        # (r"(\d{1,3}\.){3}\d{1,3}", "Raw IP address found"), # Too noisy
    ]

    def scan_directory(self, dir_path: Path) -> List[str]:
        findings = []
        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = Path(root) / file
                
                # Skip harmless files
                if file_path.suffix in ['.md', '.txt', '.rst', '.png', '.jpg']:
                    continue
                
                is_setup_file = file in ["setup.py", "install.js", "preinstall.js", "postinstall.js"]
                
                try:
                    with open(file_path, "r", errors="ignore") as f:
                        content = f.read()
                        
                    # 1. Regex Scan
                    for pattern, desc in self.SUSPICIOUS_PATTERNS:
                        # Network/Process patterns only check in strictly setup/install files
                        if "Network request" in desc or "Process execution" in desc or "Socket" in desc or "Shell" in desc:
                            if not is_setup_file:
                                continue
                        
                        if re.search(pattern, content):
                            if "test" in str(file_path).lower():
                                continue
                            findings.append(f"{desc} in {file}")

                    # 2. Python AST Scan (setup.py / __init__.py usually critical)
                    if file_path.suffix == ".py":
                        if "test" not in str(file_path).lower():
                            findings.extend(self._scan_python_ast(content, file))
                        
                except Exception:
                    pass
                    
        return list(set(findings))

    def _scan_python_ast(self, content: str, filename: str) -> List[str]:
        findings = []
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                # Detect: exec(base64.b64decode(...))
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == "exec":
                        findings.append(f"Direct use of 'exec' in {filename}")
                        
                    # Detect: os.system(...)
                    if isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "system":
                            findings.append(f"Direct shell execution (os.system) in {filename}")
        except SyntaxError:
            pass
        return findings
