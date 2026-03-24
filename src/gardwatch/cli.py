import asyncio
import argparse
import sys
import logging
from pathlib import Path
from typing import Optional
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

                        # If package not found, return error report
                        if package_info is None:
                            from .models import ScoreComponent
                            error_report = TrustReport(
                                status="CRITICAL",
                                score=0,
                                reason="Package not found",
                                components=[
                                    ScoreComponent(
                                        label="Package Not Found",
                                        score=0,
                                        description=f"Package '{dep.name}' not found in {dep.ecosystem} registry",
                                        category="Error"
                                    )
                                ],
                                details=[f"Package '{dep.name}' does not exist in {dep.ecosystem}"]
                            )
                            progress.update(task, advance=1)
                            return dep, error_report

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
                            logging.info(f"Starting deep scan for {dep.name}")
                            check_summary = scanner.get_check_summary()
                            logging.info(f"Deep scan checks: {check_summary}")
                            version = version_details.get("versionKey", {}).get("version")
                            logging.info(f"Version: {version}")
                            dl_url = None
                            if dep.ecosystem == "npm":
                                dl_url = await registry_client.get_npm_download_url(dep.name, version)
                            elif dep.ecosystem == "pypi":
                                dl_url = await registry_client.get_pypi_download_url(dep.name, version)
                            else:
                                if deep_scan:
                                    console.print(f"[yellow]Warning: Deep scan source download not yet supported for {dep.ecosystem}[/yellow]")

                            logging.info(f"Download URL: {dl_url}")
                            from .models import ScoreComponent

                            # Get total check count for display
                            total_checks = len([c for c in scanner.CHECKS if c.enabled]) + len(scanner.AST_CHECKS)

                            if dl_url:
                                try:
                                    logging.info(f"Downloading and extracting package...")
                                    async with downloader.download_and_extract(dl_url) as extract_path:
                                        logging.info(f"Extracted to {extract_path}, scanning...")
                                        findings = scanner.scan_directory(extract_path)
                                        logging.info(f"Scan complete. Findings: {len(findings) if findings else 0}")

                                        if findings:
                                            report.score = 0
                                            report.status = "CRITICAL"
                                            report.components.append(ScoreComponent(
                                                label="Deep Scan",
                                                score=-100,
                                                description=f"Malicious patterns detected ({len(findings)} issues found in {total_checks} checks)",
                                                category="Security"
                                            ))
                                            report.details.extend(findings)
                                        else:
                                            report.components.append(ScoreComponent(
                                                label="Deep Scan",
                                                score=0,
                                                description=f"Passed all {total_checks} security checks",
                                                category="Security"
                                            ))
                                except Exception as e:
                                    logging.error(f"Deep scan failed for {dep.name}: {type(e).__name__}: {e}")
                                    import traceback
                                    logging.debug(traceback.format_exc())
                                    report.components.append(ScoreComponent(
                                        label="Deep Scan",
                                        score=0,
                                        description=f"Scan failed: {type(e).__name__}",
                                        category="Security"
                                    ))
                            else:
                                # Package cannot be downloaded - critical failure
                                report.score = 0
                                report.status = "CRITICAL"
                                report.components.append(ScoreComponent(
                                    label="Deep Scan",
                                    score=-100,
                                    description="Package not downloadable from registry",
                                    category="Security"
                                ))
                                report.details.append(f"Package exists in metadata but cannot be downloaded from {dep.ecosystem} registry")
        
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

async def run_scan(package: str, ecosystem: str, deep: bool, version: Optional[str] = None):
    engine = TrustEngine()
    dep = Dependency(name=package, ecosystem=ecosystem, version=version)
    version_str = f"@{version}" if version else ""
    is_critical = await analyze_dependencies([dep], engine, f"Analysis of {package}{version_str} ({ecosystem})", deep, show_safe=True)
    if is_critical:
        sys.exit(1)

def main():
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
    scan_parser.add_argument("--version", help="Specific version to scan (optional, defaults to latest)")
    scan_parser.add_argument("--deep", action="store_true", help="Perform deep code analysis (downloads packages)")
    scan_parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    group = scan_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--npm", action="store_true", help="Check as npm package")
    group.add_argument("--pypi", action="store_true", help="Check as PyPI package")
    group.add_argument("--go", action="store_true", help="Check as Go module")
    group.add_argument("--cargo", action="store_true", help="Check as Rust crate")
    group.add_argument("--maven", action="store_true", help="Check as Java artifact")
    group.add_argument("--nuget", action="store_true", help="Check as .NET package")

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

        version = getattr(args, "version", None)
        asyncio.run(run_scan(args.package, ecosystem, args.deep, version))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
