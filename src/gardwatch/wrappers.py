"""
Package manager wrapper functionality for gardwatch.
"""
import asyncio
import subprocess
import sys
import re
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.prompt import Confirm

from .models import Dependency
from .engine import TrustEngine
from .parsers.javascript import PackageJsonParser
from .parsers.python import RequirementsTxtParser

console = Console()


class PackageManagerWrapper:
    """Base class for package manager wrappers."""

    def __init__(self, manager_name: str, ecosystem: str):
        self.manager_name = manager_name
        self.ecosystem = ecosystem
        self.real_binary = self._find_real_binary()

    def _find_real_binary(self) -> str:
        """Find the real package manager binary."""
        # For now, just return the manager name
        # In a production setup, we might need to find the actual binary path
        # to avoid recursion if the wrapper is installed in PATH
        return self.manager_name

    def should_scan(self, args: list[str]) -> bool:
        """Determine if the command should trigger a scan."""
        raise NotImplementedError

    def extract_packages(self, args: list[str]) -> list[tuple[str, Optional[str]]]:
        """
        Extract packages from command arguments.
        Returns list of (package_name, version) tuples.
        """
        raise NotImplementedError

    async def scan_packages(self, packages: list[tuple[str, Optional[str]]], check_deps: bool = True) -> tuple[bool, bool]:
        """
        Scan packages and return (has_critical, has_suspicious).
        """
        if not packages:
            return False, False

        # Import here to avoid circular dependency
        from .cli import analyze_dependencies

        engine = TrustEngine()
        dependencies = [
            Dependency(name=name, version=version, ecosystem=self.ecosystem)
            for name, version in packages
        ]

        console.print(f"\n[bold cyan]🛡️  GardWatch Security Scan[/bold cyan]")
        console.print(f"Scanning {len(packages)} package(s) before installation...\n")

        # Use the existing analyze_dependencies function
        # For now, do a simple critical check
        # We can enhance this later to track suspicious separately
        has_critical = await analyze_dependencies(
            dependencies,
            engine,
            f"Security Scan for {self.manager_name}",
            deep_scan=False,
            show_safe=False
        )

        # TODO: Track suspicious separately
        # For now, we'll return False for suspicious
        return has_critical, False

    def prompt_user(self, has_critical: bool, has_suspicious: bool) -> bool:
        """
        Prompt user for confirmation if needed.
        Returns True if should proceed, False otherwise.
        """
        if has_critical:
            console.print("\n[bold red]⚠️  CRITICAL security issues detected![/bold red]")
            return Confirm.ask("Do you want to proceed with installation anyway?", default=False)

        if has_suspicious:
            console.print("\n[bold yellow]⚠️  Suspicious packages detected[/bold yellow]")
            console.print("Proceeding with installation...")
            return True

        return True

    def execute(self, args: list[str]) -> int:
        """Execute the real package manager with the given arguments."""
        try:
            # Execute the real package manager
            result = subprocess.run(
                [self.real_binary] + args,
                check=False
            )
            return result.returncode
        except Exception as e:
            console.print(f"[red]Error executing {self.manager_name}: {e}[/red]")
            return 1

    def get_dependency_file(self) -> Optional[Path]:
        """Get the dependency file path if it exists."""
        raise NotImplementedError

    async def parse_dependency_file(self, file_path: Path) -> list[Dependency]:
        """Parse the dependency file and return dependencies."""
        raise NotImplementedError

    async def run(self, args: list[str]) -> int:
        """Main wrapper logic."""
        # Check if we should scan
        if not self.should_scan(args):
            # Pass through directly
            return self.execute(args)

        # Extract packages from command line
        packages = self.extract_packages(args)

        # If no packages in command line, check if we should parse dependency file
        if not packages:
            dep_file = self.get_dependency_file()
            if dep_file and dep_file.exists():
                console.print(f"\n[cyan]No packages specified, scanning dependencies from {dep_file.name}...[/cyan]")
                dependencies = await self.parse_dependency_file(dep_file)
                if dependencies:
                    packages = [(dep.name, dep.version) for dep in dependencies]

        if not packages:
            # No packages to scan, pass through
            return self.execute(args)

        # Scan packages
        has_critical, has_suspicious = await self.scan_packages(packages)

        # Prompt user if needed
        if not self.prompt_user(has_critical, has_suspicious):
            console.print("\n[yellow]Installation cancelled by user[/yellow]")
            return 1

        # Execute the real package manager
        console.print(f"\n[green]Proceeding with {self.manager_name} installation...[/green]\n")
        return self.execute(args)


class NpmWrapper(PackageManagerWrapper):
    """npm package manager wrapper."""

    def __init__(self):
        super().__init__("npm", "npm")

    def should_scan(self, args: list[str]) -> bool:
        """Check if this is an install/update command."""
        if not args:
            return False

        # Commands that install packages
        install_commands = {"install", "i", "add", "update", "upgrade"}
        return args[0] in install_commands

    def get_dependency_file(self) -> Optional[Path]:
        """Get package.json if it exists."""
        package_json = Path("package.json")
        return package_json if package_json.exists() else None

    async def parse_dependency_file(self, file_path: Path) -> list[Dependency]:
        """Parse package.json and return dependencies."""
        parser = PackageJsonParser()
        dependencies = []
        async for dep in parser.parse(file_path):
            dependencies.append(dep)
        return dependencies

    def extract_packages(self, args: list[str]) -> list[tuple[str, Optional[str]]]:
        """
        Extract npm packages from arguments.
        Handles formats like:
        - package
        - package@version
        - @scope/package
        - @scope/package@version
        """
        packages = []

        # Skip the command itself (install, i, add, etc.)
        for arg in args[1:]:
            # Skip flags
            if arg.startswith('-'):
                continue

            # Parse package[@version]
            # Handle scoped packages: @scope/package[@version]
            if arg.startswith('@'):
                # Scoped package
                match = re.match(r'^(@[^/]+/[^@]+)(?:@(.+))?$', arg)
                if match:
                    name, version = match.groups()
                    packages.append((name, version))
            else:
                # Regular package
                if '@' in arg:
                    name, version = arg.rsplit('@', 1)
                    packages.append((name, version))
                else:
                    packages.append((arg, None))

        return packages


class PipWrapper(PackageManagerWrapper):
    """pip package manager wrapper."""

    def __init__(self):
        super().__init__("pip", "pypi")

    def should_scan(self, args: list[str]) -> bool:
        """Check if this is an install/upgrade command."""
        if not args:
            return False

        # Commands that install packages
        return args[0] == "install"

    def get_dependency_file(self) -> Optional[Path]:
        """Get requirements.txt if it exists."""
        requirements_txt = Path("requirements.txt")
        return requirements_txt if requirements_txt.exists() else None

    async def parse_dependency_file(self, file_path: Path) -> list[Dependency]:
        """Parse requirements.txt and return dependencies."""
        parser = RequirementsTxtParser()
        dependencies = []
        async for dep in parser.parse(file_path):
            dependencies.append(dep)
        return dependencies

    def extract_packages(self, args: list[str]) -> list[tuple[str, Optional[str]]]:
        """
        Extract pip packages from arguments.
        Handles formats like:
        - package
        - package==version
        - package>=version
        - -r requirements.txt (TODO: parse the file)
        """
        packages = []
        skip_next = False

        for i, arg in enumerate(args[1:], 1):
            if skip_next:
                skip_next = False
                continue

            # Skip flags
            if arg.startswith('-'):
                # Check for -r flag
                if arg == '-r' or arg == '--requirement':
                    # Next arg is the requirements file
                    # For now, we'll skip this - we could parse it later
                    skip_next = True
                continue

            # Parse package[==version]
            # Remove version specifiers
            match = re.match(r'^([a-zA-Z0-9_-]+)(?:[=<>!]=?.*)?$', arg)
            if match:
                name = match.group(1)
                # Try to extract exact version if using ==
                version = None
                if '==' in arg:
                    version = arg.split('==')[1]
                packages.append((name, version))

        return packages


async def run_npm_wrapper(args: list[str]) -> int:
    """Run npm wrapper with given arguments."""
    wrapper = NpmWrapper()
    return await wrapper.run(args)


async def run_pip_wrapper(args: list[str]) -> int:
    """Run pip wrapper with given arguments."""
    wrapper = PipWrapper()
    return await wrapper.run(args)
