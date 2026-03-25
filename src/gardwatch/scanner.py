import ast
import re
import os
import logging
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field

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
    languages: List[str] = field(default_factory=list)  # e.g., ["python", "javascript"], empty = all languages
    file_extensions: List[str] = field(default_factory=list)  # e.g., [".pth"], empty = all extensions

class SourceScanner:
    # Ecosystem file extension mappings
    ECOSYSTEM_FILE_EXTENSIONS = {
        'pypi': ['.py', '.pth'],
        'npm': ['.js', '.mjs', '.cjs'],
    }

    ECOSYSTEM_SETUP_FILES = {
        'pypi': ['setup.py'],
        'npm': ['package.json', 'install.js', 'preinstall.js', 'postinstall.js'],
    }

    # Registry of all security checks
    CHECKS = [
        # Python checks
        SecurityCheck(
            name="py_eval_detection",
            description="Use of eval() (code execution)",
            pattern=r"eval\(",
            category="code_execution",
            languages=["python"],
            setup_only=True
        ),
        SecurityCheck(
            name="py_exec_detection",
            description="Use of exec() (code execution)",
            pattern=r"exec\(",
            category="code_execution",
            languages=["python"],
            setup_only=True
        ),
        SecurityCheck(
            name="py_base64_exec",
            description="Base64 decode with exec (code execution)",
            pattern=r"(base64\.b64decode.*exec\(|exec\(.*base64\.b64decode)",
            category="code_execution",
            languages=["python"],
            setup_only=True
        ),
        SecurityCheck(
            name="py_import_semicolon",
            description="Import with semicolon (malicious payload)",
            pattern=r"^import\s+[,.\s\w]+;\s*\S",
            category="code_execution",
            languages=["python"],
            file_extensions=[".pth"]
        ),
        SecurityCheck(
            name="py_subprocess_call",
            description="Process execution (subprocess.call)",
            pattern=r"subprocess\.call",
            category="process",
            setup_only=True,
            languages=["python"]
        ),
        SecurityCheck(
            name="py_subprocess_popen",
            description="Process execution (subprocess.Popen)",
            pattern=r"subprocess\.Popen",
            category="process",
            setup_only=True,
            languages=["python"]
        ),
        SecurityCheck(
            name="py_os_system",
            description="Shell execution (os.system)",
            pattern=r"os\.system",
            category="process",
            setup_only=True,
            languages=["python"]
        ),
        SecurityCheck(
            name="py_socket_creation",
            description="Socket creation (possible C2 connection)",
            pattern=r"socket\.socket",
            category="network",
            setup_only=True,
            languages=["python"]
        ),
        SecurityCheck(
            name="py_urlopen",
            description="Network request (urllib.urlopen)",
            pattern=r"urlopen\(",
            category="network",
            setup_only=True,
            languages=["python"]
        ),
        SecurityCheck(
            name="py_requests_get",
            description="Network request (requests.get)",
            pattern=r"requests\.get",
            category="network",
            setup_only=True,
            languages=["python"]
        ),

        # JavaScript/Node.js checks
        SecurityCheck(
            name="js_eval",
            description="Use of eval() (code execution)",
            pattern=r"eval\(",
            category="code_execution",
            languages=["javascript"]
        ),
        SecurityCheck(
            name="js_child_process_exec",
            description="Process execution (child_process.exec)",
            pattern=r"(require\(['\"]child_process['\"]\)|child_process)\.(exec|execSync|spawn|spawnSync)",
            category="process",
            setup_only=True,
            languages=["javascript"]
        ),
        SecurityCheck(
            name="js_fs_read",
            description="File system access (fs.readFile)",
            pattern=r"(require\(['\"]fs['\"]\)|fs)\.(readFile|readFileSync|readdir|readdirSync)",
            category="file_access",
            setup_only=True,
            languages=["javascript"]
        ),
        SecurityCheck(
            name="js_network_http",
            description="Network request (http/https)",
            pattern=r"require\(['\"]https?['\"]",
            category="network",
            setup_only=True,
            languages=["javascript"]
        ),
        SecurityCheck(
            name="js_fetch",
            description="Network request (fetch)",
            pattern=r"fetch\(",
            category="network",
            setup_only=True,
            languages=["javascript"]
        ),

        # Shell/generic checks
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
            category="file_access",
            setup_only=True
        ),
        SecurityCheck(
            name="ssh_keys",
            description="Accessing SSH private keys",
            pattern=r"\.ssh/id_rsa",
            category="file_access",
            setup_only=True
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

    def scan_directory(self, dir_path: Path, ecosystem: Optional[str] = None) -> List[str]:
        """Scan a directory for malicious patterns.

        Args:
            dir_path: Path to directory to scan
            ecosystem: Package ecosystem (e.g., 'pypi', 'npm'). Used to filter language-specific checks.
        """
        findings = []
        file_count = 0
        skipped_count = 0
        scanned_count = 0

        logger.info(f"Starting directory scan of {dir_path} (ecosystem: {ecosystem})")

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

                # Skip files not relevant to the ecosystem
                if ecosystem and ecosystem in self.ECOSYSTEM_FILE_EXTENSIONS:
                    allowed_extensions = self.ECOSYSTEM_FILE_EXTENSIONS[ecosystem]
                    allowed_setup_files = self.ECOSYSTEM_SETUP_FILES.get(ecosystem, [])
                    if file_path.suffix not in allowed_extensions and file not in allowed_setup_files:
                        logger.debug(f"  Skipping file not relevant to {ecosystem}: {rel_path}")
                        skipped_count += 1
                        continue

                # Determine if this is a setup/install file
                all_setup_files = []
                for setup_files in self.ECOSYSTEM_SETUP_FILES.values():
                    all_setup_files.extend(setup_files)
                # .pth files are ALWAYS treated as setup files since they execute at Python startup
                is_setup_file = file in all_setup_files or file_path.suffix == ".pth"

                # Determine file language
                file_language = None
                if file_path.suffix in [".py", ".pth"]:
                    file_language = "python"
                elif file_path.suffix in [".js", ".mjs", ".cjs"]:
                    file_language = "javascript"

                try:
                    logger.info(f"  Scanning: {rel_path} (setup file: {is_setup_file}, language: {file_language})")
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

                        # Skip language-specific checks if file language doesn't match
                        if check.languages and file_language not in check.languages:
                            continue

                        # Skip checks if ecosystem doesn't match the language
                        # e.g., don't run JS checks on Python packages
                        if ecosystem and check.languages:
                            ecosystem_language_map = {
                                'pypi': 'python',
                                'npm': 'javascript'
                            }
                            expected_lang = ecosystem_language_map.get(ecosystem)
                            if expected_lang and expected_lang not in check.languages:
                                continue

                        # Skip file-extension-specific checks if extension doesn't match
                        if check.file_extensions and file_path.suffix not in check.file_extensions:
                            continue

                        # Allow checks with no language/extension specification to run on all files
                        if re.search(check.pattern, content):
                            finding = f"{check.description} in {file}"
                            file_findings.append(finding)
                            logger.warning(f"    ⚠️  FOUND: {check.description}")

                    # 2. Python AST Scan (only on setup files to avoid false positives)
                    if file_path.suffix == ".py" and is_setup_file:
                        logger.debug(f"    Running Python AST analysis...")
                        ast_findings = self._scan_python_ast(content, file)
                        for finding in ast_findings:
                            logger.warning(f"    ⚠️  FOUND: {finding}")
                        file_findings.extend(ast_findings)

                    # 3. Flag .pth files (executed at Python startup)
                    if file_path.suffix == ".pth":
                        logger.warning(f"    ⚠️  .pth file detected (executes at Python startup)")
                        file_findings.append(f".pth file present: {file} (auto-executed at Python startup)")

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
