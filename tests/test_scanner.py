import pytest
from pathlib import Path
import tempfile
import shutil
import os
from depsentry.scanner import SourceScanner

@pytest.fixture
def scanner():
    return SourceScanner()

@pytest.fixture
def temp_dir():
    path = tempfile.mkdtemp()
    yield Path(path)
    shutil.rmtree(path)

def test_scan_empty_dir(scanner, temp_dir):
    findings = scanner.scan_directory(temp_dir)
    assert findings == []

def test_scan_suspicious_python_ast(scanner, temp_dir):
    # Test AST detection of exec(base64...)
    py_file = temp_dir / "malicious.py"
    py_file.write_text("import base64\nexec(base64.b64decode('cHJpbnQoImhlbGxvIik='))")
    
    findings = scanner.scan_directory(temp_dir)
    assert any("Direct use of 'exec'" in f for f in findings)

def test_scan_shell_execution(scanner, temp_dir):
    # Test detection of os.system
    py_file = temp_dir / "setup.py"
    py_file.write_text("import os\nos.system('rm -rf /')")
    
    findings = scanner.scan_directory(temp_dir)
    assert any("Direct shell execution (os.system)" in f for f in findings)
    assert any("Shell execution" in f for f in findings)

def test_scan_sensitive_files(scanner, temp_dir):
    # Test detection of /etc/shadow or .ssh/id_rsa
    py_file = temp_dir / "lib.py"
    py_file.write_text("open('/etc/shadow')")
    
    findings = scanner.scan_directory(temp_dir)
    assert any("Accessing sensitive file" in f for f in findings)

def test_scan_network_in_setup(scanner, temp_dir):
    # Network requests should be flagged in setup.py
    setup_file = temp_dir / "setup.py"
    setup_file.write_text("import requests\nrequests.get('http://malicious.com')")
    
    findings = scanner.scan_directory(temp_dir)
    assert any("Network request" in f for f in findings)

def test_scan_network_ignore_in_regular_file(scanner, temp_dir):
    # Network requests are common in regular files, should NOT be flagged
    regular_file = temp_dir / "app.py"
    regular_file.write_text("import requests\nrequests.get('http://google.com')")
    
    findings = scanner.scan_directory(temp_dir)
    # Filter out AST findings if any, but regex should not hit for "Network request"
    network_findings = [f for f in findings if "Network request" in f]
    assert network_findings == []

def test_scan_ignore_test_files(scanner, temp_dir):
    # Suspicious patterns in test files should be ignored
    test_file = temp_dir / "test_malicious.py"
    test_file.write_text("os.system('something')")
    
    findings = scanner.scan_directory(temp_dir)
    assert findings == []

def test_scan_ignore_safe_extensions(scanner, temp_dir):
    # MD files etc should be ignored
    readme = temp_dir / "README.md"
    readme.write_text("eval(something)")
    
    findings = scanner.scan_directory(temp_dir)
    assert findings == []
