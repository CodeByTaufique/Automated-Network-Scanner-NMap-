#!/usr/bin/env python3
"""
Automated Network Scanner
==========================
Wraps Nmap to scan a target, parse open ports/services, and generate
a report (text/JSON/HTML).

IMPORTANT: Only scan hosts/networks you own or have explicit permission
to test. Unauthorized scanning may violate laws (e.g. CFAA) or your
network provider's terms of service.

Requirements:
    - Nmap installed and on PATH (https://nmap.org/download.html)
    - Python 3.8+

Usage:
    python3 scanner.py 192.168.1.1
    python3 scanner.py 192.168.1.0/24 --ports 1-1000
    python3 scanner.py scanme.nmap.org --ports 22,80,443 --html report.html
    python3 scanner.py 192.168.1.1 --top-ports 100 --json report.json
"""

import argparse
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

class PortResult:
    def __init__(self, port, protocol, state, service, product, version, extrainfo):
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service
        self.product = product
        self.version = version
        self.extrainfo = extrainfo

    def service_summary(self):
        parts = [p for p in (self.product, self.version) if p]
        summary = " ".join(parts)
        if self.extrainfo:
            summary += f" ({self.extrainfo})"
        return summary.strip() or "unknown"

    def to_dict(self):
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
        }


class HostResult:
    def __init__(self, address, hostname, status):
        self.address = address
        self.hostname = hostname
        self.status = status
        self.ports = []

    def to_dict(self):
        return {
            "address": self.address,
            "hostname": self.hostname,
            "status": self.status,
            "ports": [p.to_dict() for p in self.ports],
        }


# --------------------------------------------------------------------------
# Core scanner
# --------------------------------------------------------------------------

class NetworkScanner:
    def __init__(self, target, ports=None, top_ports=None, timing="-T4",
                 service_detection=True, extra_args=None):
        self.target = target
        self.ports = ports
        self.top_ports = top_ports
        self.timing = timing
        self.service_detection = service_detection
        self.extra_args = extra_args or []
        self.hosts = []
        self.scan_start = None
        self.scan_end = None
        self.command_used = None

    @staticmethod
    def check_nmap_installed():
        return shutil.which("nmap") is not None

    def _build_command(self, xml_out_path):
        cmd = ["nmap"]

        if self.service_detection:
            cmd.append("-sV")  # service/version detection

        if self.ports:
            cmd += ["-p", self.ports]
        elif self.top_ports:
            cmd += ["--top-ports", str(self.top_ports)]

        if self.timing:
            cmd.append(self.timing)

        cmd += self.extra_args
        cmd += ["-oX", str(xml_out_path), self.target]
        return cmd

    def scan(self, verbose=True):
        if not self.check_nmap_installed():
            raise RuntimeError(
                "Nmap not found on PATH. Install it from https://nmap.org/download.html "
                "(e.g. `sudo apt install nmap` on Debian/Ubuntu, `brew install nmap` on macOS)."
            )

        xml_out_path = Path.cwd() / f".scan_{datetime.now():%Y%m%d_%H%M%S}.xml"
        cmd = self._build_command(xml_out_path)
        self.command_used = " ".join(cmd)

        if verbose:
            print(f"[*] Running: {self.command_used}")

        self.scan_start = datetime.now()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,
            )
        except FileNotFoundError:
            raise RuntimeError("Nmap not found on PATH.")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Scan timed out after 1 hour.")
        self.scan_end = datetime.now()

        if result.returncode != 0:
            raise RuntimeError(
                f"Nmap exited with code {result.returncode}.\nstderr:\n{result.stderr}"
            )

        if not xml_out_path.exists():
            raise RuntimeError("Nmap did not produce an XML output file.")

        try:
            self._parse_xml(xml_out_path)
        finally:
            xml_out_path.unlink(missing_ok=True)

        if verbose:
            print(f"[*] Scan complete. {len(self.hosts)} host(s) found.")

        return self.hosts

    def _parse_xml(self, xml_path):
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host_el in root.findall("host"):
            status_el = host_el.find("status")
            status = status_el.get("state") if status_el is not None else "unknown"

            addr_el = host_el.find("address")
            address = addr_el.get("addr") if addr_el is not None else "unknown"

            hostname = None
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                hn_el = hostnames_el.find("hostname")
                if hn_el is not None:
                    hostname = hn_el.get("name")

            host_result = HostResult(address, hostname, status)

            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    port_num = int(port_el.get("portid"))
                    protocol = port_el.get("protocol")

                    state_el = port_el.find("state")
                    state = state_el.get("state") if state_el is not None else "unknown"

                    service_el = port_el.find("service")
                    service = product = version = extrainfo = None
                    if service_el is not None:
                        service = service_el.get("name")
                        product = service_el.get("product")
                        version = service_el.get("version")
                        extrainfo = service_el.get("extrainfo")

                    # Only keep ports that are open (skip closed/filtered noise
                    # unless the user wants everything — kept simple here).
                    if state == "open":
                        host_result.ports.append(
                            PortResult(port_num, protocol, state, service,
                                       product, version, extrainfo)
                        )

            self.hosts.append(host_result)

    def duration_seconds(self):
        if self.scan_start and self.scan_end:
            return (self.scan_end - self.scan_start).total_seconds()
        return None

    def to_dict(self):
        return {
            "target": self.target,
            "command": self.command_used,
            "scan_start": self.scan_start.isoformat() if self.scan_start else None,
            "scan_end": self.scan_end.isoformat() if self.scan_end else None,
            "duration_seconds": self.duration_seconds(),
            "hosts": [h.to_dict() for h in self.hosts],
        }


# --------------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------------

def generate_text_report(scanner: NetworkScanner) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append("NETWORK SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Target:    {scanner.target}")
    lines.append(f"Command:   {scanner.command_used}")
    lines.append(f"Started:   {scanner.scan_start}")
    lines.append(f"Finished:  {scanner.scan_end}")
    lines.append(f"Duration:  {scanner.duration_seconds():.1f}s")
    lines.append("")

    if not scanner.hosts:
        lines.append("No hosts found (all hosts down or filtered).")
        return "\n".join(lines)

    for host in scanner.hosts:
        lines.append("-" * 60)
        label = f"{host.address}"
        if host.hostname:
            label += f" ({host.hostname})"
        lines.append(f"Host: {label}  [{host.status}]")
        lines.append("-" * 60)

        if not host.ports:
            lines.append("  No open ports found.")
        else:
            lines.append(f"  {'PORT':<10}{'STATE':<8}{'SERVICE':<15}{'VERSION'}")
            for p in host.ports:
                lines.append(
                    f"  {str(p.port) + '/' + p.protocol:<10}{p.state:<8}"
                    f"{p.service or '?':<15}{p.service_summary()}"
                )
        lines.append("")

    return "\n".join(lines)


def generate_json_report(scanner: NetworkScanner) -> str:
    return json.dumps(scanner.to_dict(), indent=2)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Scan Report - {target}</title>
<style>
  :root {{
    --bg: #0f1117;
    --panel: #171a23;
    --border: #2a2e3a;
    --text: #e6e8ee;
    --muted: #9aa1b1;
    --accent: #5eead4;
    --danger: #f87171;
    --warn: #fbbf24;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 40px 20px;
  }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 1.6rem; margin-bottom: 4px; }}
  .subtitle {{ color: var(--muted); margin-bottom: 28px; font-size: 0.9rem; }}
  .meta {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 28px;
    font-size: 0.85rem;
    color: var(--muted);
  }}
  .meta div {{ margin: 3px 0; }}
  .meta code {{ color: var(--accent); }}
  .host {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 20px;
    overflow: hidden;
  }}
  .host-header {{
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .host-header h2 {{ font-size: 1.05rem; margin: 0; }}
  .badge {{
    font-size: 0.72rem;
    padding: 3px 10px;
    border-radius: 999px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }}
  .badge.up {{ background: rgba(94,234,212,0.15); color: var(--accent); }}
  .badge.down {{ background: rgba(248,113,113,0.15); color: var(--danger); }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{
    text-align: left;
    padding: 10px 20px;
    font-size: 0.88rem;
    border-bottom: 1px solid var(--border);
  }}
  th {{ color: var(--muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; }}
  tr:last-child td {{ border-bottom: none; }}
  .port-num {{ color: var(--accent); font-weight: 600; font-family: monospace; }}
  .no-ports {{ padding: 16px 20px; color: var(--muted); font-size: 0.88rem; font-style: italic; }}
  .footer {{ text-align: center; color: var(--muted); font-size: 0.78rem; margin-top: 30px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Network Scan Report</h1>
  <div class="subtitle">Target: {target}</div>

  <div class="meta">
    <div>Command: <code>{command}</code></div>
    <div>Started: {scan_start}</div>
    <div>Finished: {scan_end}</div>
    <div>Duration: {duration:.1f}s</div>
    <div>Hosts found: {host_count}</div>
  </div>

  {hosts_html}

  <div class="footer">Generated by Automated Network Scanner &middot; {generated_at}</div>
</div>
</body>
</html>
"""

HOST_TEMPLATE = """
  <div class="host">
    <div class="host-header">
      <h2>{address}{hostname_suffix}</h2>
      <span class="badge {status_class}">{status}</span>
    </div>
    {body}
  </div>
"""

TABLE_TEMPLATE = """
    <table>
      <thead>
        <tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
"""

ROW_TEMPLATE = """<tr>
          <td class="port-num">{port}</td>
          <td>{protocol}</td>
          <td>{state}</td>
          <td>{service}</td>
          <td>{version}</td>
        </tr>"""


def _escape(text):
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def generate_html_report(scanner: NetworkScanner) -> str:
    hosts_html_parts = []

    for host in scanner.hosts:
        hostname_suffix = f" <span style='color:var(--muted); font-weight:400;'>({_escape(host.hostname)})</span>" if host.hostname else ""
        status_class = "up" if host.status == "up" else "down"

        if host.ports:
            rows = "\n        ".join(
                ROW_TEMPLATE.format(
                    port=f"{p.port}",
                    protocol=_escape(p.protocol),
                    state=_escape(p.state),
                    service=_escape(p.service or "?"),
                    version=_escape(p.service_summary()),
                )
                for p in host.ports
            )
            body = TABLE_TEMPLATE.format(rows=rows)
        else:
            body = '<div class="no-ports">No open ports found.</div>'

        hosts_html_parts.append(
            HOST_TEMPLATE.format(
                address=_escape(host.address),
                hostname_suffix=hostname_suffix,
                status_class=status_class,
                status=_escape(host.status),
                body=body,
            )
        )

    return HTML_TEMPLATE.format(
        target=_escape(scanner.target),
        command=_escape(scanner.command_used),
        scan_start=scanner.scan_start,
        scan_end=scanner.scan_end,
        duration=scanner.duration_seconds() or 0,
        host_count=len(scanner.hosts),
        hosts_html="\n".join(hosts_html_parts),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


# --------------------------------------------------------------------------
# Safety helper: warn on scanning targets outside common private ranges
# --------------------------------------------------------------------------

def looks_like_public_target(target: str) -> bool:
    """Best-effort check to nudge users about scanning targets they may not own.
    This is advisory only, not a security control."""
    candidate = target.split("/")[0]
    try:
        ip = ipaddress.ip_address(candidate)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        # Hostname - try resolving
        try:
            resolved = socket.gethostbyname(candidate)
            ip = ipaddress.ip_address(resolved)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        except (socket.gaierror, ValueError):
            return False  # unknown, don't block


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Automated Network Scanner - scans a target with Nmap, "
                     "parses results, and generates a report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py 192.168.1.1
  python3 scanner.py 192.168.1.0/24 --ports 1-1000
  python3 scanner.py scanme.nmap.org --top-ports 100 --html report.html
  python3 scanner.py 10.0.0.5 --ports 22,80,443 --json report.json --text report.txt

Only scan systems you own or are authorized to test.
""",
    )
    parser.add_argument("target", help="IP address, hostname, or CIDR range to scan")
    parser.add_argument("--ports", help="Port spec, e.g. '22,80,443' or '1-1000'")
    parser.add_argument("--top-ports", type=int, help="Scan the N most common ports")
    parser.add_argument("--no-service-detection", action="store_true",
                         help="Skip -sV service/version detection (faster)")
    parser.add_argument("--timing", default="-T4",
                         help="Nmap timing template (default: -T4)")
    parser.add_argument("--html", metavar="FILE", help="Write an HTML report to FILE")
    parser.add_argument("--json", metavar="FILE", help="Write a JSON report to FILE")
    parser.add_argument("--text", metavar="FILE", help="Write a plain-text report to FILE")
    parser.add_argument("--yes", action="store_true",
                         help="Skip the confirmation prompt for public-looking targets")

    args = parser.parse_args()

    if looks_like_public_target(args.target) and not args.yes:
        print(f"[!] '{args.target}' does not look like a private/local address.")
        print("[!] Only scan systems you own or have explicit permission to test.")
        confirm = input("Continue anyway? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            sys.exit(0)

    scanner = NetworkScanner(
        target=args.target,
        ports=args.ports,
        top_ports=args.top_ports,
        timing=args.timing,
        service_detection=not args.no_service_detection,
    )

    try:
        scanner.scan()
    except RuntimeError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Always print the text report to stdout
    print()
    print(generate_text_report(scanner))

    if args.json:
        Path(args.json).write_text(generate_json_report(scanner))
        print(f"[*] JSON report written to {args.json}")

    if args.text:
        Path(args.text).write_text(generate_text_report(scanner))
        print(f"[*] Text report written to {args.text}")

    if args.html:
        Path(args.html).write_text(generate_html_report(scanner))
        print(f"[*] HTML report written to {args.html}")


if __name__ == "__main__":
    main()
