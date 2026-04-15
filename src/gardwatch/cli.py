import asyncio
import argparse
import sys
import logging
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
import httpx

from .parsers.python import RequirementsTxtParser
from .parsers.javascript import PackageJsonParser
from .parsers.pipfile import PipfileParser
from .parsers.go import GoModParser
from .parsers.rust import CargoTomlParser
from .parsers.java import MavenPomParser
from .parsers.csharp import CSharpProjectParser
from .parsers.cyclonedx import CycloneDXParser
from .clients.depsdev import DepsDevClient
from .clients.npm import NpmClient
from .clients.pypi import PyPIClient
from .clients.nuget import NugetClient
from .clients.cargo import CargoClient
from .clients.registry import RegistryClient
from .download import PackageDownloader
from .scanner import SourceScanner
from .models import Dependency
from .engine import TrustEngine
from .report import TrustReport
from .wrappers import run_npm_wrapper, run_pip_wrapper
from .auth import login as auth_login, logout as auth_logout, is_logged_in, get_valid_token
from .clients.gardera import check_dependencies

console = Console()

def render_report(dep: Dependency, report: TrustReport):
    """Render a detailed scorecard for a dependency."""

    # Status Color
    color_map = {
        "SAFE": "green",
        "SUSPICIOUS": "yellow",
        "CRITICAL": "red"
    }
    color = color_map.get(report.status, "white")

    # Header
    title = Text(f"{dep.name} ({dep.ecosystem})", style="bold white")
    subtitle = Text(f"{report.status} - Trust Score: {report.score}/100", style=f"bold {color}")

    # Components Table
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column(style="white")

    # Sort components by score descending
    sorted_components = sorted(report.components, key=lambda c: c.score, reverse=True)

    for comp in sorted_components:
        pts = f"{'+'}{comp.score}" if comp.score > 0 else str(comp.score)
        grid.add_row(
            f"{pts} pts",
            f"[bold]{comp.label}:[/bold] {comp.description}"
        )

    # Details/Warnings
    if report.details:
        grid.add_row("", "")
        for detail in report.details:
            grid.add_row("WARN", f"[red]{detail}[/red]")

    console.print(Panel(
        grid,
        title=title,
        subtitle=subtitle,
        border_style=color,
        expand=False
    ))

async def analyze_dependencies(dependencies: list[Dependency], engine: TrustEngine, title: str, deep_scan: bool = False, show_safe: bool = False) -> bool:
    # Use Gardera API when authenticated, fall back to local analysis
    if get_valid_token():
        return await _analyze_dependencies_remote(dependencies, title, show_safe)
    return await _analyze_dependencies_local(dependencies, engine, title, deep_scan, show_safe)


async def _analyze_dependencies_remote(dependencies: list[Dependency], title: str, show_safe: bool = False) -> bool:
    console.print(f"[bold]Using Gardera API for analysis[/bold]")
    console.print(f"\n[bold]{title}[/bold]")

    any_critical = False
    stats = {"SAFE": 0, "SUSPICIOUS": 0, "CRITICAL": 0}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"[green]Scanning {len(dependencies)} packages via Gardera API...", total=None)
        results = await check_dependencies(dependencies)

    for dep, report in results:
        stats[report.status] = stats.get(report.status, 0) + 1
        if report.status == "CRITICAL":
            any_critical = True
        if show_safe or report.status != "SAFE":
            render_report(dep, report)

    summary_grid = Table.grid(padding=(0, 2))
    summary_grid.add_column(style="bold white")
    summary_grid.add_column(style="bold cyan")
    summary_grid.add_row("Total Scanned:", str(len(results)))
    summary_grid.add_row("Safe:", f"[green]{stats['SAFE']}[/green]")
    summary_grid.add_row("Suspicious:", f"[yellow]{stats['SUSPICIOUS']}[/yellow]")
    summary_grid.add_row("Critical:", f"[red]{stats['CRITICAL']}[/red]")
    console.print(Panel(summary_grid, title="Scan Summary", expand=False))

    return any_critical


async def _analyze_dependencies_local(dependencies: list[Dependency], engine: TrustEngine, title: str, deep_scan: bool = False, show_safe: bool = False) -> bool:
    console.print(f"\n[bold]{title}[/bold]")

    any_critical = False
    stats = {"SAFE": 0, "SUSPICIOUS": 0, "CRITICAL": 0}

    async with httpx.AsyncClient() as http_client:
        deps_client = DepsDevClient(http_client)
        registry_client = RegistryClient(http_client)
        downloader = PackageDownloader(http_client)
        scanner = SourceScanner()

        # Ecosystem clients
        clients = {
            "npm": NpmClient(http_client),
            "pypi": PyPIClient(http_client),
            "nuget": NugetClient(http_client),
            "cargo": CargoClient(http_client)
        }

        semaphore = asyncio.Semaphore(10)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[green]Scanning {len(dependencies)} packages...", total=len(dependencies))

            async def check_dep(dep):
                    async with semaphore:
                        # 1. Fetch Package Info AND Version Details
                        package_info, version_details = await deps_client.get_package_and_version(dep)

                        # 2. Fetch Downloads
                        download_count = None
                        client = clients.get(dep.ecosystem)
                        if client:
                            download_count = await client.get_download_count(dep.name)

                        # 3. Fetch Scorecard / Project Data
                        scorecard = None
                        project_data = None
                        if version_details:
                            projects = version_details.get("relatedProjects", [])
                            source_project = next(
                                (p["projectKey"]["id"] for p in projects if p.get("relationType") == "SOURCE_REPO"),
                                None
                            )
                            if source_project:
                                project_data = await deps_client.get_project_data(source_project)
                                if project_data:
                                    scorecard = project_data.get("scorecard")

                        report = engine.evaluate(dep, package_info, version_details, scorecard, download_count, project_data)

                        if deep_scan and version_details:
                            version = version_details.get("versionKey", {}).get("version")
                            dl_url = None
                            if dep.ecosystem == "npm":
                                dl_url = await registry_client.get_npm_download_url(dep.name, version)
                            elif dep.ecosystem == "pypi":
                                dl_url = await registry_client.get_pypi_download_url(dep.name, version)
                            else:
                                if deep_scan:
                                    console.print(f"[yellow]Warning: Deep scan source download not yet supported for {dep.ecosystem}[/yellow]")

                            if dl_url:
                                try:
                                    async with downloader.download_and_extract(dl_url) as extract_path:
                                        findings = scanner.scan_directory(extract_path)
                                        if findings:
                                            report.score = 0
                                            report.status = "CRITICAL"
                                            # Pydantic update
                                            from .models import ScoreComponent
                                            report.components.append(ScoreComponent(label="Deep Scan", score=-100, description="Malicious patterns found", category="Security"))
                                            report.details.extend(findings)
                                except Exception:
                                    pass

                        progress.update(task, advance=1)
                        return dep, report
            results = await asyncio.gather(*(check_dep(dep) for dep in dependencies))

            for dep, report in results:
                stats[report.status] = stats.get(report.status, 0) + 1

                if report.status == "CRITICAL":
                    any_critical = True

                if show_safe or report.status != "SAFE":
                    render_report(dep, report)

    # Print Summary
    summary_grid = Table.grid(padding=(0, 2))
    summary_grid.add_column(style="bold white")
    summary_grid.add_column(style="bold cyan")
    summary_grid.add_row("Total Scanned:", str(len(dependencies)))
    summary_grid.add_row("Safe:", f"[green]{stats['SAFE']}[/green]")
    summary_grid.add_row("Suspicious:", f"[yellow]{stats['SUSPICIOUS']}[/yellow]")
    summary_grid.add_row("Critical:", f"[red]{stats['CRITICAL']}[/red]")

    console.print(Panel(summary_grid, title="Scan Summary", expand=False))

    return any_critical

async def run_analysis(files: list[str], deep: bool, force_sbom: bool = False):
    engine = TrustEngine()
    total_critical = 0

    # Standard parsers
    standard_parsers = [
        RequirementsTxtParser(),
        PackageJsonParser(),
        PipfileParser(),
        GoModParser(),
        CargoTomlParser(),
        MavenPomParser(),
        CSharpProjectParser(),
        CycloneDXParser()
    ]

    for file_str in files:
        file_path = Path(file_str)
        if not file_path.exists():
            console.print(f"[red]File not found: {file_path}[/red]")
            continue

        parser = None
        if force_sbom:
            parser = CycloneDXParser()
            # We still check if it looks like an SBOM to avoid crashing on random files
            if not parser.can_parse(file_path):
                 console.print(f"[red]File {file_path} does not appear to be a valid CycloneDX SBOM[/red]")
                 continue
        else:
            parser = next((p for p in standard_parsers if p.can_parse(file_path)), None)

        if not parser:
            console.print(f"[red]No parser found for file: {file_path}[/red]")
            continue

        dependencies = []
        async for dep in parser.parse(file_path):
            dependencies.append(dep)

        if not dependencies:
            console.print(f"[yellow]No dependencies found in {file_path}[/yellow]")
            continue

        is_critical = await analyze_dependencies(dependencies, engine, f"Analysis of {file_path.name}", deep, show_safe=False)
        if is_critical:
            total_critical += 1

    if total_critical > 0:
        console.print(f"\n[bold red]FAILURE:[/bold red] {total_critical} file(s) contained CRITICAL security risks!")
        sys.exit(1)
    else:
        console.print("\n[bold green]SUCCESS:[/bold green] No critical risks found.")
        sys.exit(0)

async def run_scan(package: str, ecosystem: str, deep: bool):
    engine = TrustEngine()
    dep = Dependency(name=package, ecosystem=ecosystem)
    is_critical = await analyze_dependencies([dep], engine, f"Analysis of {package} ({ecosystem})", deep, show_safe=True)
    if is_critical:
        sys.exit(1)

def setup_wrappers(managers: list[str]):
    """Install wrapper aliases for package managers."""
    import os
    import shutil

    # Determine which managers to set up
    if "all" in managers:
        managers = ["npm", "pip"]

    # Detect shell
    shell = os.environ.get("SHELL", "")
    shell_name = Path(shell).name if shell else None

    if not shell_name or shell_name not in ["bash", "zsh", "fish"]:
        console.print("[yellow]Warning: Could not detect shell type (bash/zsh/fish)[/yellow]")
        console.print("You may need to manually add aliases to your shell configuration file.")
        shell_name = "bash"  # Default to bash

    # Determine RC file
    home = Path.home()
    if shell_name == "bash":
        rc_file = home / ".bashrc"
    elif shell_name == "zsh":
        rc_file = home / ".zshrc"
    elif shell_name == "fish":
        rc_file = home / ".config" / "fish" / "config.fish"
    else:
        rc_file = home / ".bashrc"

    # Find gardwatch path
    gardwatch_path = shutil.which("gardwatch")
    if not gardwatch_path:
        console.print("[red]Error: gardwatch not found in PATH[/red]")
        console.print("Please ensure gardwatch is installed and in your PATH")
        sys.exit(1)

    # Generate aliases
    aliases = []
    for manager in managers:
        if shell_name == "fish":
            alias_line = f'alias {manager}="gardwatch {manager}"'
        else:
            alias_line = f'alias {manager}="gardwatch {manager}"'
        aliases.append(alias_line)

    # Check if aliases already exist
    existing_content = ""
    if rc_file.exists():
        existing_content = rc_file.read_text()

    # Add aliases if not present
    new_aliases = []
    for alias_line in aliases:
        if alias_line not in existing_content:
            new_aliases.append(alias_line)

    if not new_aliases:
        console.print("[green]All requested aliases are already installed[/green]")
        return

    # Add marker comments for easy removal
    marker_start = "# >>> gardwatch wrappers >>>"
    marker_end = "# <<< gardwatch wrappers <<<"

    # Check if marker exists
    if marker_start in existing_content:
        console.print("[yellow]GardWatch wrapper section already exists in {rc_file}[/yellow]")
        console.print("Remove it first with: gardwatch remove-wrapper")
        sys.exit(1)

    # Append to RC file
    with rc_file.open("a") as f:
        f.write(f"\n{marker_start}\n")
        for alias_line in new_aliases:
            f.write(f"{alias_line}\n")
        f.write(f"{marker_end}\n")

    console.print(f"[green]✓ Aliases installed to {rc_file}[/green]")
    for manager in managers:
        console.print(f"  - {manager} → gardwatch {manager}")

    console.print(f"\n[bold]To activate the aliases, run:[/bold]")
    console.print(f"  source {rc_file}")
    console.print("\nOr restart your terminal.")

def remove_wrappers(managers: list[str]):
    """Remove wrapper aliases for package managers."""
    import os

    # Detect shell
    shell = os.environ.get("SHELL", "")
    shell_name = Path(shell).name if shell else None

    if not shell_name or shell_name not in ["bash", "zsh", "fish"]:
        shell_name = "bash"

    # Determine RC file
    home = Path.home()
    if shell_name == "bash":
        rc_file = home / ".bashrc"
    elif shell_name == "zsh":
        rc_file = home / ".zshrc"
    elif shell_name == "fish":
        rc_file = home / ".config" / "fish" / "config.fish"
    else:
        rc_file = home / ".bashrc"

    if not rc_file.exists():
        console.print(f"[yellow]No configuration file found at {rc_file}[/yellow]")
        return

    # Read content
    content = rc_file.read_text()

    # Find and remove gardwatch section
    marker_start = "# >>> gardwatch wrappers >>>"
    marker_end = "# <<< gardwatch wrappers <<<"

    if marker_start not in content:
        console.print("[yellow]No gardwatch wrappers found in configuration file[/yellow]")
        return

    # Remove the section
    lines = content.split('\n')
    new_lines = []
    skip = False

    for line in lines:
        if marker_start in line:
            skip = True
            continue
        if marker_end in line:
            skip = False
            continue
        if not skip:
            new_lines.append(line)

    # Write back
    rc_file.write_text('\n'.join(new_lines))

    console.print(f"[green]✓ GardWatch wrappers removed from {rc_file}[/green]")
    console.print("\n[bold]To deactivate the aliases, run:[/bold]")
    console.print(f"  source {rc_file}")
    console.print("\nOr restart your terminal.")

def main():
    # Handle wrapper commands specially to avoid argparse interfering with pass-through arguments
    # Check if "npm" or "pip" appears anywhere in sys.argv (after the script name)
    wrapper_command = None
    wrapper_index = None

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg in ["npm", "pip"]:
            wrapper_command = arg
            wrapper_index = i
            break

    if wrapper_command:
        # Everything after the wrapper command goes to the underlying package manager
        wrapper_args = sys.argv[wrapper_index + 1:]

        if wrapper_command == "npm":
            exit_code = asyncio.run(run_npm_wrapper(wrapper_args))
            sys.exit(exit_code)
        elif wrapper_command == "pip":
            exit_code = asyncio.run(run_pip_wrapper(wrapper_args))
            sys.exit(exit_code)

    # Normal argparse flow for other commands
    parser = argparse.ArgumentParser(description="GardWatch: Protect your dependencies.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze file command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze dependency files")
    analyze_parser.add_argument("files", nargs="+", help="Dependency files to analyze")
    analyze_parser.add_argument("--deep", action="store_true", help="Perform deep code analysis (downloads packages)")
    analyze_parser.add_argument("--sbom", action="store_true", help="Treat input files as CycloneDX SBOMs")
    analyze_parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    # Scan single package command
    scan_parser = subparsers.add_parser("scan", help="Scan a single package")
    scan_parser.add_argument("package", help="Package name")
    scan_parser.add_argument("--deep", action="store_true", help="Perform deep code analysis (downloads packages)")
    scan_parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    group = scan_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--npm", action="store_true", help="Check as npm package")
    group.add_argument("--pypi", action="store_true", help="Check as PyPI package")
    group.add_argument("--go", action="store_true", help="Check as Go module")
    group.add_argument("--cargo", action="store_true", help="Check as Rust crate")
    group.add_argument("--maven", action="store_true", help="Check as Java artifact")
    group.add_argument("--nuget", action="store_true", help="Check as .NET package")

    # Auth commands
    subparsers.add_parser("login", help="Log in to Gardera via browser")
    subparsers.add_parser("logout", help="Log out and revoke tokens")
    subparsers.add_parser("status", help="Show authentication status")

    # setup-wrapper command
    setup_parser = subparsers.add_parser("setup-wrapper", help="Install wrapper aliases for package managers")
    setup_parser.add_argument("managers", nargs="*", choices=["npm", "pip", "all"], help="Package managers to set up (default: all)")

    # remove-wrapper command
    remove_parser = subparsers.add_parser("remove-wrapper", help="Remove wrapper aliases for package managers")
    remove_parser.add_argument("managers", nargs="*", choices=["npm", "pip", "all"], help="Package managers to remove (default: all)")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr
    )

    if args.command == "analyze":
        asyncio.run(run_analysis(args.files, args.deep, args.sbom))
    elif args.command == "scan":
        ecosystem = "npm"
        if args.npm: ecosystem = "npm"
        elif args.pypi: ecosystem = "pypi"
        elif args.go: ecosystem = "go"
        elif args.cargo: ecosystem = "cargo"
        elif args.maven: ecosystem = "maven"
        elif args.nuget: ecosystem = "nuget"

        asyncio.run(run_scan(args.package, ecosystem, args.deep))
    elif args.command == "login":
        if is_logged_in():
            console.print("[yellow]Already logged in. Run 'gardwatch logout' first to re-authenticate.[/yellow]")
            sys.exit(0)
        console.print("Opening browser to log in to Gardera...")
        try:
            auth_login()
            console.print("[green]Successfully logged in to Gardera.[/green]")
        except Exception as e:
            console.print(f"[red]Login failed: {e}[/red]")
            sys.exit(1)
    elif args.command == "logout":
        try:
            auth_logout()
            console.print("[green]Logged out of Gardera.[/green]")
        except RuntimeError as e:
            console.print(f"[yellow]{e}[/yellow]")
    elif args.command == "status":
        if is_logged_in():
            console.print("[green]Logged in to Gardera.[/green]")
        else:
            console.print("[yellow]Not logged in. Run 'gardwatch login' to authenticate.[/yellow]")
    elif args.command == "setup-wrapper":
        setup_wrappers(args.managers if args.managers else ["all"])
    elif args.command == "remove-wrapper":
        remove_wrappers(args.managers if args.managers else ["all"])
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
