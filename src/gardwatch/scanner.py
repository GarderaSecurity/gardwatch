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
            name="py_code_execution",
            description="Dynamic code execution (eval/exec/compile)",
            pattern=r"(eval\(|exec\(|compile\()",
            category="code_execution",
            languages=["python"],
            setup_only=True
        ),
        SecurityCheck(
            name="py_base64_exec",
            description="Base64 decode with exec (obfuscated code execution)",
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
            name="py_shell_execution",
            description="Shell/process execution (subprocess/os.system/os.popen/pty.spawn)",
            pattern=r"(subprocess\.(call|check_call|check_output|run|Popen)|os\.(system|popen|spawn[lv]p?e?)|pty\.spawn|commands\.(getoutput|getstatusoutput))",
            category="process",
            setup_only=True,
            languages=["python"]
        ),
        SecurityCheck(
            name="py_network_activity",
            description="Network activity (socket/urllib/requests/httpx)",
            pattern=r"(socket\.socket|urlopen\(|requests\.(get|post|put|delete|request)|httpx\.(get|post|Client))",
            category="network",
            setup_only=True,
            languages=["python"]
        ),

        # JavaScript/Node.js checks
        SecurityCheck(
            name="js_code_execution",
            description="Dynamic code execution (eval/Function)",
            pattern=r"(eval\(|Function\()",
            category="code_execution",
            languages=["javascript"],
            setup_only=True
        ),
        SecurityCheck(
            name="js_shell_execution",
            description="Shell/process execution (child_process)",
            pattern=r"(require\(['\"]child_process['\"]\)|child_process)\.(exec|execSync|spawn|spawnSync|fork)",
            category="process",
            setup_only=True,
            languages=["javascript"]
        ),
        SecurityCheck(
            name="js_file_access",
            description="File system access (fs module)",
            pattern=r"(require\(['\"]fs['\"]\)|fs)\.(readFile|readFileSync|readdir|readdirSync|writeFile|writeFileSync)",
            category="file_access",
            setup_only=True,
            languages=["javascript"]
        ),
        SecurityCheck(
            name="js_network_activity",
            description="Network activity (http/https/fetch)",
            pattern=r"(require\(['\"]https?['\"]\)|fetch\(|axios\.(get|post))",
            category="network",
            setup_only=True,
            languages=["javascript"]
        ),

        # Shell/generic checks
        SecurityCheck(
            name="shell_download_tools",
            description="Shell download tools (curl/wget)",
            pattern=r"(curl\s+|wget\s+)",
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
            pattern=r"\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts|config)",
            category="file_access",
            setup_only=True
        ),
        SecurityCheck(
            name="cloud_metadata_server",
            description="Accessing cloud metadata server (credential theft)",
            pattern=r"(169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2)",
            category="network",
            setup_only=True
        ),
        SecurityCheck(
            name="aws_credentials",
            description="Accessing AWS credentials",
            pattern=r"\.aws/(credentials|config)",
            category="file_access",
            setup_only=True
        ),
        SecurityCheck(
            name="gcp_credentials",
            description="Accessing GCP credentials",
            pattern=r"\.config/gcloud",
            category="file_access",
            setup_only=True
        ),
        SecurityCheck(
            name="azure_credentials",
            description="Accessing Azure credentials",
            pattern=r"\.azure/",
            category="file_access",
            setup_only=True
        ),
        SecurityCheck(
            name="bitcoin_wallet",
            description="Accessing Bitcoin wallet",
            pattern=r"(\.bitcoin/(bitcoin\.conf|wallet\.dat)|wallet\.dat)",
            category="file_access",
            setup_only=True
        ),
        SecurityCheck(
            name="ethereum_wallet",
            description="Accessing Ethereum wallet",
            pattern=r"\.ethereum/keystore",
            category="file_access",
            setup_only=True
        ),
        SecurityCheck(
            name="crypto_wallets",
            description="Accessing cryptocurrency wallets",
            pattern=r"\.(solana|litecoin|dogecoin|zcash|dash|ripple)/",
            category="file_access",
            setup_only=True
        ),
        SecurityCheck(
            name="k8s_secrets",
            description="Accessing Kubernetes secrets API",
            pattern=r"/api/v1/(namespaces/[^/]+/)?secrets",
            category="network",
            setup_only=True
        ),
        SecurityCheck(
            name="systemd_persistence",
            description="Creating systemd service (persistence mechanism)",
            pattern=r"(\.config/systemd/user/|/etc/systemd/system/|systemctl\s+enable)",
            category="process",
            setup_only=True
        ),
        SecurityCheck(
            name="env_dump",
            description="Dumping environment variables",
            pattern=r"(printenv|os\.environ\[|getenv\()",
            category="process",
            setup_only=True
        ),
        SecurityCheck(
            name="passwd_file",
            description="Accessing /etc/passwd",
            pattern=r"/etc/passwd",
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
