import ast
import re
import os
import logging
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SecurityCheck:
    """Represents a single security check with metadata."""
    name: str
    description: str
    pattern: str
    category: str  # e.g., "code_execution", "network", "file_access", "process"
    setup_only: bool = False  # Only check in setup/install files
    enabled: bool = True

class SourceScanner:
    # Registry of all security checks
    CHECKS = [
        SecurityCheck(
            name="eval_detection",
            description="Use of eval() (code execution)",
            pattern=r"eval\(",
            category="code_execution"
        ),
        SecurityCheck(
            name="subprocess_call",
            description="Process execution (subprocess.call)",
            pattern=r"subprocess\.call",
            category="process",
            setup_only=True
        ),
        SecurityCheck(
            name="subprocess_popen",
            description="Process execution (subprocess.Popen)",
            pattern=r"subprocess\.Popen",
            category="process",
            setup_only=True
        ),
        SecurityCheck(
            name="os_system",
            description="Shell execution (os.system)",
            pattern=r"os\.system",
            category="process",
            setup_only=True
        ),
        SecurityCheck(
            name="socket_creation",
            description="Socket creation (possible C2 connection)",
            pattern=r"socket\.socket",
            category="network",
            setup_only=True
        ),
        SecurityCheck(
            name="urlopen",
            description="Network request (urllib.urlopen)",
            pattern=r"urlopen\(",
            category="network",
            setup_only=True
        ),
        SecurityCheck(
            name="requests_get",
            description="Network request (requests.get)",
            pattern=r"requests\.get",
            category="network",
            setup_only=True
        ),
        SecurityCheck(
            name="curl_usage",
            description="Curl usage in shell/script",
            pattern=r"curl\s+",
            category="network",
            setup_only=True
        ),
        SecurityCheck(
            name="wget_usage",
            description="Wget usage in shell/script",
            pattern=r"wget\s+",
            category="network",
            setup_only=True
        ),
        SecurityCheck(
            name="etc_shadow",
            description="Accessing /etc/shadow",
            pattern=r"/etc/shadow",
            category="file_access"
        ),
        SecurityCheck(
            name="ssh_keys",
            description="Accessing SSH private keys",
            pattern=r"\.ssh/id_rsa",
            category="file_access"
        ),
        # Disabled checks
        # SecurityCheck(
        #     name="base64_decode",
        #     description="Base64 decoding",
        #     pattern=r"base64\.b64decode",
        #     category="code_execution",
        #     enabled=False  # Too noisy, AST handles exec(decode)
        # ),
    ]

    AST_CHECKS = [
        "Direct exec() calls (potential code execution)",
        "os.system() calls (shell execution)",
        "exec(base64.b64decode()) patterns"
    ]

    def get_check_summary(self) -> str:
        """Returns a human-readable summary of enabled checks."""
        categories = {}
        for check in self.CHECKS:
            if check.enabled:
                if check.category not in categories:
                    categories[check.category] = []
                categories[check.category].append(check.description)

        summary_parts = []
        category_labels = {
            "code_execution": "Code Execution",
            "process": "Process/Shell Execution",
            "network": "Network Activity",
            "file_access": "Sensitive File Access"
        }

        for cat, checks in categories.items():
            label = category_labels.get(cat, cat)
            summary_parts.append(f"{label} ({len(checks)} checks)")

        summary_parts.append(f"Python AST Analysis ({len(self.AST_CHECKS)} checks)")

        return "; ".join(summary_parts)

    def scan_directory(self, dir_path: Path) -> List[str]:
        findings = []
        file_count = 0
        skipped_count = 0
        scanned_count = 0

        logger.info(f"Starting directory scan of {dir_path}")

        for root, _, files in os.walk(dir_path):
            for file in files:
                file_count += 1
                file_path = Path(root) / file
                rel_path = file_path.relative_to(dir_path)

                # Skip harmless files
                if file_path.suffix in ['.md', '.txt', '.rst', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico']:
                    logger.debug(f"  Skipping harmless file: {rel_path}")
                    skipped_count += 1
                    continue

                # Skip test files
                if "test" in str(file_path).lower():
                    logger.debug(f"  Skipping test file: {rel_path}")
                    skipped_count += 1
                    continue

                is_setup_file = file in ["setup.py", "install.js", "preinstall.js", "postinstall.js"]

                try:
                    logger.info(f"  Scanning: {rel_path} (setup file: {is_setup_file})")
                    scanned_count += 1

                    with open(file_path, "r", errors="ignore") as f:
                        content = f.read()

                    file_findings = []

                    # 1. Regex Scan using check registry
                    for check in self.CHECKS:
                        if not check.enabled:
                            continue

                        # Skip setup-only checks if not in a setup file
                        if check.setup_only and not is_setup_file:
                            continue

                        if re.search(check.pattern, content):
                            finding = f"{check.description} in {file}"
                            file_findings.append(finding)
                            logger.warning(f"    ⚠️  FOUND: {check.description}")

                    # 2. Python AST Scan (setup.py / __init__.py usually critical)
                    if file_path.suffix == ".py":
                        logger.debug(f"    Running Python AST analysis...")
                        ast_findings = self._scan_python_ast(content, file)
                        for finding in ast_findings:
                            logger.warning(f"    ⚠️  FOUND: {finding}")
                        file_findings.extend(ast_findings)

                    if not file_findings:
                        logger.info(f"    ✓ Clean")

                    findings.extend(file_findings)

                except Exception as e:
                    logger.debug(f"    Error scanning {rel_path}: {e}")
                    pass

        logger.info(f"Scan complete: {file_count} files total, {scanned_count} scanned, {skipped_count} skipped, {len(findings)} findings")

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
