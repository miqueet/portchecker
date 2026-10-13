#!/usr/bin/env python3
"""Check whether TCP ports are open on one or more hosts.

Usage example:
    python portopen.py 1.1.1.1 80
"""

from __future__ import annotations

import argparse
import csv
import functools
import io
import json
import os
import re
import socket
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, fields

__version__ = "2.0.0"

OPEN, CLOSED, FILTERED, ERROR = "open", "closed", "filtered", "error"
STATES = (OPEN, CLOSED, FILTERED, ERROR)
STATE_COLORS = {OPEN: "32", CLOSED: "31", FILTERED: "33", ERROR: "31"}

NAGIOS_STATES = ("OK", "WARNING", "CRITICAL", "UNKNOWN")

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
]

PORT_SPEC = re.compile(r"\d+(-\d+)?(,\d+(-\d+)?)*")

EXAMPLES = """\
examples:
  portopen.py 1.1.1.1 80                    check a single port
  portopen.py example.com 22,80,443         check several ports
  portopen.py example.com 1-1024 --open-only
  portopen.py db:5432 cache:6379 web:https  host:port pairs (names work too)
  portopen.py example.com --common -b       common ports, with service banners
  portopen.py -f hosts.txt -p 22 -o json    targets from a file, JSON output
  portopen.py db:5432 --wait 60 && ./migrate
  portopen.py example.com -p 443 --nagios -w 0.5 -c 1

exit status:
  0 every port is open, 1 at least one is not, 2 usage error
  with --nagios: 0 OK, 1 WARNING, 2 CRITICAL
"""


@dataclass
class Result:
    host: str
    port: int
    state: str
    address: str = ""
    service: str = ""
    latency_ms: float | None = None
    banner: str = ""
    error: str = ""

    @property
    def target(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


def parse_port(token):
    """Turn '443' or a service name such as 'https' into a port number."""
    token = token.strip()
    if token.isdigit():
        port = int(token)
    else:
        try:
            port = socket.getservbyname(token, "tcp")
        except OSError:
            raise ValueError(f"unknown port or service name: {token!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range (1-65535): {port}")
    return port


def parse_ports(spec):
    """Expand a spec such as '22,80,8000-8010,https' into unique port numbers."""
    ports = []
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        span = re.fullmatch(r"(\d+)-(\d+)", token)
        if span:
            low, high = parse_port(span[1]), parse_port(span[2])
            if low > high:
                raise ValueError(f"invalid port range: {token!r}")
            ports.extend(range(low, high + 1))
        else:
            ports.append(parse_port(token))
    if not ports:
        raise ValueError(f"no ports in {spec!r}")
    return list(dict.fromkeys(ports))


def split_target(target):
    """Split 'host', 'host:ports', '[ipv6]:ports' or a bare IPv6 address."""
    if target.startswith("["):
        host, bracket, rest = target[1:].partition("]")
        if not bracket or (rest and not rest.startswith(":")):
            raise ValueError(f"malformed target: {target!r}")
        return host, rest[1:] or None
    if target.count(":") == 1:
        host, _, ports = target.partition(":")
        return host, ports or None
    return target, None


def read_target_file(path):
    """Read whitespace-separated targets from a file ('-' for stdin); '#' starts a comment."""
    if path == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(path) as handle:
            lines = handle.read().splitlines()
    targets = []
    for line in lines:
        targets.extend(line.split("#", 1)[0].split())
    return targets


def build_targets(positional, ports=None, common=False, file=None):
    """Combine CLI arguments into an ordered, de-duplicated list of (host, port) pairs."""
    positional = list(positional)
    default_ports = parse_ports(ports) if ports else []
    # Keep the original "portopen.py HOST PORT" form working: a trailing port
    # spec applies to every host that doesn't name its own ports.
    if (not ports and positional and PORT_SPEC.fullmatch(positional[-1])
            and (len(positional) > 1 or file)):
        default_ports = parse_ports(positional.pop())
    if common:
        default_ports = list(dict.fromkeys(default_ports + COMMON_PORTS))
    if file:
        positional += read_target_file(file)

    targets = []
    for item in positional:
        host, spec = split_target(item)
        if not host:
            raise ValueError(f"missing host in {item!r}")
        host_ports = parse_ports(spec) if spec else default_ports
        if not host_ports:
            raise ValueError(f"no port given for {host!r}; use HOST:PORT, -p PORTS or --common")
        targets.extend((host, port) for port in host_ports)
    return list(dict.fromkeys(targets))


def resolve(host, family=socket.AF_UNSPEC):
    """Resolve host to (family, sockaddr) for its preferred address, or return an error message."""
    try:
        info = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        return f"DNS lookup failed: {getattr(exc, 'strerror', None) or exc}"
    family, _, _, _, sockaddr = info[0]
    return family, sockaddr


@functools.lru_cache(maxsize=None)
def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def read_banner(sock, limit=200):
    """Return whatever a service sends straight after connecting, flattened to one line."""
    try:
        data = sock.recv(1024)
    except OSError:
        return ""
    text = "".join(ch if ch.isprintable() else " " for ch in data.decode("utf-8", "replace"))
    return " ".join(text.split())[:limit]


def check_port(host, port, addr, timeout=2.0, banner=False):
    """Attempt one TCP connection and classify the outcome."""
    family, sockaddr = addr
    sockaddr = (sockaddr[0], port) + tuple(sockaddr[2:])
    result = Result(host, port, ERROR, address=sockaddr[0])
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        start = time.perf_counter()
        try:
            sock.connect(sockaddr)
        except socket.timeout:
            result.state = FILTERED
        except ConnectionRefusedError:
            result.state = CLOSED
        except OSError as exc:
            result.error = exc.strerror or str(exc)
        else:
            result.state = OPEN
            result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
            if banner:
                result.banner = read_banner(sock)
    return result


def probe(host, port, addr, timeout=2.0, retries=0, banner=False):
    """check_port with retries; a refused connection is definitive and never retried."""
    if isinstance(addr, str):
        return Result(host, port, ERROR, error=addr)
    for _ in range(retries + 1):
        result = check_port(host, port, addr, timeout, banner)
        if result.state in (OPEN, CLOSED):
            break
    return result


def scan(targets, timeout=2.0, family=socket.AF_UNSPEC, workers=100, retries=0, banner=False):
    """Check (host, port) pairs concurrently and return results in the same order."""
    if not targets:
        return []
    hosts = list(dict.fromkeys(host for host, _ in targets))
    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets))))
    try:
        addrs = dict(zip(hosts, pool.map(lambda host: resolve(host, family), hosts)))
        results = list(pool.map(
            lambda t: probe(t[0], t[1], addrs[t[0]], timeout, retries, banner), targets))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    # getservbyport isn't thread-safe, so look names up here rather than in the workers.
    for result in results:
        result.service = service_name(result.port)
    return results


def wait_for(targets, deadline, interval=1.0, **scan_options):
    """Re-scan until every target is open or the monotonic deadline passes."""
    latest = {}
    pending = targets
    while True:
        for result in scan(pending, **scan_options):
            latest[(result.host, result.port)] = result
        pending = [t for t in pending if latest[t].state != OPEN]
        remaining = deadline - time.monotonic()
        if not pending or remaining <= 0:
            return [latest[t] for t in targets]
        time.sleep(min(interval, remaining))


def format_text(results, color=False):
    header = ["HOST", "PORT", "STATE", "SERVICE", "LATENCY"]
    rows = []
    for r in results:
        host = r.host if r.address in ("", r.host) else f"{r.host} ({r.address})"
        latency = "-" if r.latency_ms is None else f"{r.latency_ms:.1f} ms"
        rows.append([host, str(r.port), r.state, r.service or "-", latency])
    notes = [r.banner or r.error for r in results]
    if any(notes):
        header.append("NOTE")
        for row, note in zip(rows, notes):
            row.append(note)

    widths = [max(len(row[i]) for row in [header] + rows) for i in range(len(header))]
    lines = []
    for row in [header] + rows:
        cells = [cell.ljust(width) for cell, width in zip(row, widths)]
        if color and row is not header:
            cells[2] = f"\033[{STATE_COLORS[row[2]]}m{cells[2]}\033[0m"
        lines.append("  ".join(cells).rstrip())
    return "\n".join(lines)


def format_summary(results, elapsed):
    counts = Counter(r.state for r in results)
    hosts = len({r.host for r in results})
    breakdown = ", ".join(f"{counts[state]} {state}" for state in STATES if counts[state])
    return (f"{len(results)} port(s) on {hosts} host(s) checked in {elapsed:.2f}s: "
            f"{breakdown}")


def format_json(results):
    return json.dumps([asdict(r) for r in results], indent=2)


def format_csv(results):
    names = [f.name for f in fields(Result)]
    rows = [{name: getattr(r, name) for name in names} for r in results]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=names, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().rstrip("\n")


def nagios_report(results, warning=None, critical=None, timeout=2.0):
    """Build a Nagios/Icinga plugin status line; returns (exit_code, line)."""
    problems, slow_critical, slow_warning = [], [], []
    for r in results:
        if r.state != OPEN:
            problems.append(f"{r.target} {r.state}" + (f" ({r.error})" if r.error else ""))
            continue
        seconds = r.latency_ms / 1000
        slow = f"{r.target} responded in {seconds:.3f}s"
        if critical is not None and seconds > critical:
            slow_critical.append(slow)
        elif warning is not None and seconds > warning:
            slow_warning.append(slow)

    if problems or slow_critical:
        code, message = 2, ", ".join(problems + slow_critical)
    elif slow_warning:
        code, message = 1, ", ".join(slow_warning)
    elif len(results) == 1:
        code, message = 0, f"{results[0].target} open in {results[0].latency_ms / 1000:.3f}s"
    else:
        code, message = 0, f"{len(results)}/{len(results)} ports open"

    def threshold(value):
        return "" if value is None else f"{value:g}"

    perfdata = " ".join(
        f"'{r.target}'={r.latency_ms / 1000:.6f}s;{threshold(warning)};{threshold(critical)};0;{timeout:g}"
        for r in results if r.state == OPEN
    )
    line = f"PORT {NAGIOS_STATES[code]} - {message}"
    return code, f"{line} | {perfdata}" if perfdata else line


def positive_float(value):
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError(f"must be greater than 0: {value}")
    return number


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError(f"must be greater than 0: {value}")
    return number


def non_negative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError(f"must not be negative: {value}")
    return number


def build_parser():
    parser = argparse.ArgumentParser(
        prog="portopen.py",
        description="Check whether TCP ports are open on one or more hosts.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets", nargs="*", metavar="TARGET",
        help="HOST, HOST:PORTS or [IPv6]:PORTS; a trailing port spec (e.g. "
             "'1.1.1.1 80') applies to every host given without ports")

    selection = parser.add_argument_group("what to check")
    selection.add_argument(
        "-p", "--ports", metavar="PORTS",
        help="ports for hosts given without ports: 22,80,443 or 8000-8100 or ssh,https")
    selection.add_argument(
        "--common", action="store_true",
        help=f"also check {len(COMMON_PORTS)} commonly used ports")
    selection.add_argument(
        "-f", "--file", metavar="FILE",
        help="read more targets from FILE ('-' for stdin), '#' comments allowed")
    family = selection.add_mutually_exclusive_group()
    family.add_argument("-4", dest="family", action="store_const", const=socket.AF_INET,
                        default=socket.AF_UNSPEC, help="use IPv4 only")
    family.add_argument("-6", dest="family", action="store_const", const=socket.AF_INET6,
                        help="use IPv6 only")

    behaviour = parser.add_argument_group("how to check")
    behaviour.add_argument("-t", "--timeout", type=positive_float, default=2.0, metavar="SECONDS",
                           help="connection timeout per attempt (default: 2)")
    behaviour.add_argument("-r", "--retries", type=non_negative_int, default=0, metavar="N",
                           help="retry ports that time out or error N more times (default: 0)")
    behaviour.add_argument("--workers", type=positive_int, default=100, metavar="N",
                           help="number of concurrent connections (default: 100)")
    behaviour.add_argument("-b", "--banner", action="store_true",
                           help="show what a service sends on connect (SSH, SMTP, FTP, ...); "
                                "waits up to the timeout for silent services")
    behaviour.add_argument("--wait", type=positive_float, metavar="SECONDS",
                           help="keep checking until every port is open or SECONDS pass")
    behaviour.add_argument("--interval", type=positive_float, default=1.0, metavar="SECONDS",
                           help="pause between --wait rounds (default: 1)")

    output = parser.add_argument_group("output")
    formats = output.add_mutually_exclusive_group()
    formats.add_argument("-o", "--output", choices=("text", "json", "csv"), default="text",
                         help="output format (default: text)")
    formats.add_argument("--nagios", action="store_true",
                         help="behave as a Nagios/Icinga plugin: one status line with "
                              "perfdata and exit codes 0/1/2")
    output.add_argument("-w", "--warning", type=positive_float, metavar="SECONDS",
                        help="with --nagios, WARNING when a connect takes longer than this")
    output.add_argument("-c", "--critical", type=positive_float, metavar="SECONDS",
                        help="with --nagios, CRITICAL when a connect takes longer than this")
    output.add_argument("--open-only", action="store_true", help="only list open ports")
    output.add_argument("-q", "--quiet", action="store_true",
                        help="print nothing; rely on the exit status")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.warning or args.critical) and not args.nagios:
        parser.error("-w/--warning and -c/--critical only apply with --nagios")
    try:
        targets = build_targets(args.targets, args.ports, args.common, args.file)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if not targets:
        parser.error("nothing to check: give at least one TARGET or use -f FILE")

    options = dict(timeout=args.timeout, family=args.family, workers=args.workers,
                   retries=args.retries, banner=args.banner)
    text_output = args.output == "text" and not args.nagios and not args.quiet
    start = time.monotonic()
    try:
        if args.wait:
            if text_output:
                print(f"Waiting up to {args.wait:g}s for {len(targets)} port(s)...",
                      file=sys.stderr)
            results = wait_for(targets, start + args.wait, args.interval, **options)
        else:
            results = scan(targets, **options)
    except KeyboardInterrupt:
        return 130
    elapsed = time.monotonic() - start

    if args.nagios:
        code, line = nagios_report(results, args.warning, args.critical, args.timeout)
        if not args.quiet:
            print(line)
        return code

    if not args.quiet:
        shown = [r for r in results if r.state == OPEN] if args.open_only else results
        if args.output == "json":
            print(format_json(shown))
        elif args.output == "csv":
            print(format_csv(shown))
        else:
            color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
            print(format_text(shown, color) if shown else "No open ports found.")
            if len(results) > 1:
                print(format_summary(results, elapsed))
    return 0 if all(r.state == OPEN for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
