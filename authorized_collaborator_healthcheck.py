#!/usr/bin/env python3
"""
Authorized Burp Collaborator/OAST-style server health checker.

Use only for servers you own or are explicitly authorized to assess.

The checker validates connectivity only:
  - DNS resolution
  - TCP connect to common Collaborator/OAST ports
  - HTTP/HTTPS basic responses
  - SMTP/SMTPS banner/connectivity

It cannot prove that a public third-party server will return interaction records
to your Burp client. That requires a trusted Collaborator server and matching
polling/secret configuration.
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests


DEFAULT_PORTS = "53,80,443,25,587,465"
DEFAULT_TIMEOUT = 6.0
DEFAULT_THREADS = 16


@dataclass
class PortCheck:
    port: int
    ok: bool
    elapsed_ms: int
    banner: str | None
    error: str | None


@dataclass
class HttpCheck:
    url: str
    ok: bool
    status: int | None
    elapsed_ms: int
    server: str | None
    content_type: str | None
    title: str | None
    error: str | None


@dataclass
class CollaboratorHealthResult:
    input_value: str
    host: str
    dns_ok: bool
    resolved_ips: list[str]
    tcp_checks: list[PortCheck]
    http_checks: list[HttpCheck]
    passed_checks: int
    total_checks: int
    failed_checks: int
    pass_rate: float
    verdict: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Allowlist-only multithreaded Collaborator/OAST health checker."
    )
    parser.add_argument("-i", "--input", required=True, help="TXT/CSV allowlist.")
    parser.add_argument("-o", "--output", help="Export path. Default: auto-generated CSV.")
    parser.add_argument(
        "--format",
        choices=("csv", "json", "jsonl"),
        default="csv",
        help="Export format. Default: csv",
    )
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        help=f"Comma-separated TCP ports. Default: {DEFAULT_PORTS}",
    )
    parser.add_argument("--column", type=int, default=0, help="CSV column index.")
    parser.add_argument("--delimiter", default=",", help="CSV delimiter.")
    parser.add_argument("--proxy", help="Optional HTTP/S proxy.")
    parser.add_argument("--verify-tls", action="store_true")
    parser.add_argument("--jsonl", action="store_true", help="Also print JSONL.")
    parser.add_argument(
        "--max-fail",
        type=int,
        default=2,
        help="Maximum failed checks still considered PASS_WITH_WARNINGS. Default: 2",
    )
    return parser.parse_args()


def load_inputs(path: str, column: int, delimiter: str) -> list[str]:
    file_path = Path(path)
    values: list[str] = []
    if file_path.suffix.lower() == ".csv":
        with file_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, delimiter=delimiter)
            for row in reader:
                if len(row) > column:
                    value = row[column].strip()
                    if value and not value.startswith("#"):
                        values.append(value)
    else:
        with file_path.open("r", encoding="utf-8-sig") as handle:
            for line in handle:
                value = line.strip()
                if value and not value.startswith("#"):
                    values.append(value)

    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        host = extract_host(value)
        if host and host not in seen:
            seen.add(host)
            deduped.append(value)
    return deduped


def extract_host(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        return parsed.hostname or ""
    if "/" in value:
        value = value.split("/", 1)[0]
    if ":" in value and value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.strip("[]")


def resolve_host(host: str) -> tuple[bool, list[str]]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False, []
    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return True, ips


def tcp_check(host: str, port: int, timeout: float) -> PortCheck:
    started = time.perf_counter()
    banner: str | None = None
    try:
        raw_socket = socket.create_connection((host, port), timeout=timeout)
        raw_socket.settimeout(timeout)
        with raw_socket:
            if port == 465:
                context = ssl.create_default_context()
                with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                    try:
                        banner = tls_socket.recv(120).decode("utf-8", "replace").strip()
                    except socket.timeout:
                        banner = None
            elif port in (25, 587):
                try:
                    banner = raw_socket.recv(120).decode("utf-8", "replace").strip()
                except socket.timeout:
                    banner = None
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return PortCheck(port=port, ok=True, elapsed_ms=elapsed_ms, banner=banner, error=None)
    except Exception as exc:  # noqa: BLE001 - per-port diagnostics.
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return PortCheck(port=port, ok=False, elapsed_ms=elapsed_ms, banner=None, error=str(exc))


def extract_title(body: str) -> str | None:
    lower = body.lower()
    start = lower.find("<title>")
    end = lower.find("</title>")
    if start == -1 or end == -1 or end <= start + 7:
        return None
    return body[start + 7 : end].strip()[:200] or None


def http_check(host: str, scheme: str, timeout: float, proxy: str | None, verify_tls: bool) -> HttpCheck:
    url = f"{scheme}://{host}/"
    started = time.perf_counter()
    session = requests.Session()
    session.headers.update({"User-Agent": "AuthorizedCollaboratorHealthcheck/1.0"})
    session.verify = verify_tls
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return HttpCheck(
            url=url,
            ok=True,
            status=response.status_code,
            elapsed_ms=elapsed_ms,
            server=response.headers.get("Server"),
            content_type=response.headers.get("Content-Type"),
            title=extract_title(response.text),
            error=None,
        )
    except requests.RequestException as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return HttpCheck(
            url=url,
            ok=False,
            status=None,
            elapsed_ms=elapsed_ms,
            server=None,
            content_type=None,
            title=None,
            error=str(exc),
        )


def score_result(
    dns_ok: bool,
    tcp_checks: list[PortCheck],
    http_checks: list[HttpCheck],
    max_fail: int,
) -> tuple[int, int, int, float, str]:
    passed_checks = 1 if dns_ok else 0
    total_checks = 1

    passed_checks += sum(1 for check in tcp_checks if check.ok)
    total_checks += len(tcp_checks)

    passed_checks += sum(1 for check in http_checks if check.ok)
    total_checks += len(http_checks)

    failed_checks = total_checks - passed_checks
    pass_rate = round((passed_checks / total_checks) * 100, 2) if total_checks else 0.0

    if failed_checks == 0:
        verdict = "PASS"
    elif failed_checks <= max_fail:
        verdict = "PASS_WITH_WARNINGS"
    else:
        verdict = "FAIL"
    return passed_checks, total_checks, failed_checks, pass_rate, verdict


def check_one(
    input_value: str,
    ports: list[int],
    timeout: float,
    proxy: str | None,
    verify_tls: bool,
    max_fail: int,
) -> CollaboratorHealthResult:
    host = extract_host(input_value)
    dns_ok, ips = resolve_host(host)
    tcp_checks = [tcp_check(host, port, timeout) for port in ports]
    http_checks = [
        http_check(host, "http", timeout, proxy, verify_tls),
        http_check(host, "https", timeout, proxy, verify_tls),
    ]
    passed_checks, total_checks, failed_checks, pass_rate, verdict = score_result(
        dns_ok, tcp_checks, http_checks, max_fail
    )
    return CollaboratorHealthResult(
        input_value=input_value,
        host=host,
        dns_ok=dns_ok,
        resolved_ips=ips,
        tcp_checks=tcp_checks,
        http_checks=http_checks,
        passed_checks=passed_checks,
        total_checks=total_checks,
        failed_checks=failed_checks,
        pass_rate=pass_rate,
        verdict=verdict,
    )


def flatten_for_csv(result: CollaboratorHealthResult) -> dict[str, str]:
    row: dict[str, str] = {
        "input_value": result.input_value,
        "host": result.host,
        "verdict": result.verdict,
        "passed_checks": str(result.passed_checks),
        "total_checks": str(result.total_checks),
        "failed_checks": str(result.failed_checks),
        "pass_rate": str(result.pass_rate),
        "dns_ok": str(result.dns_ok),
        "resolved_ips": "|".join(result.resolved_ips),
    }
    for check in result.tcp_checks:
        prefix = f"tcp_{check.port}"
        row[f"{prefix}_ok"] = str(check.ok)
        row[f"{prefix}_elapsed_ms"] = str(check.elapsed_ms)
        row[f"{prefix}_banner"] = check.banner or ""
        row[f"{prefix}_error"] = check.error or ""
    for check in result.http_checks:
        scheme = urlparse(check.url).scheme
        row[f"{scheme}_ok"] = str(check.ok)
        row[f"{scheme}_status"] = str(check.status or "")
        row[f"{scheme}_elapsed_ms"] = str(check.elapsed_ms)
        row[f"{scheme}_server"] = check.server or ""
        row[f"{scheme}_title"] = check.title or ""
        row[f"{scheme}_error"] = check.error or ""
    return row


def collaborator_csv_fieldnames(ports: list[int]) -> list[str]:
    fieldnames = [
        "input_value",
        "host",
        "verdict",
        "passed_checks",
        "total_checks",
        "failed_checks",
        "pass_rate",
        "dns_ok",
        "resolved_ips",
    ]
    for port in ports:
        prefix = f"tcp_{port}"
        fieldnames.extend(
            [
                f"{prefix}_ok",
                f"{prefix}_elapsed_ms",
                f"{prefix}_banner",
                f"{prefix}_error",
            ]
        )
    for scheme in ("http", "https"):
        fieldnames.extend(
            [
                f"{scheme}_ok",
                f"{scheme}_status",
                f"{scheme}_elapsed_ms",
                f"{scheme}_server",
                f"{scheme}_title",
                f"{scheme}_error",
            ]
        )
    return fieldnames


def export_results(path: str, fmt: str, results: list[CollaboratorHealthResult]) -> None:
    if fmt == "csv":
        rows = [flatten_for_csv(result) for result in results]
        fieldnames: list[str] = []
        for row in rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return

    with open(path, "w", encoding="utf-8") as handle:
        if fmt == "jsonl":
            for result in results:
                handle.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")
        else:
            json.dump([asdict(result) for result in results], handle, ensure_ascii=False, indent=2)


def print_summary(result: CollaboratorHealthResult) -> None:
    tcp_ok = ",".join(str(check.port) for check in result.tcp_checks if check.ok) or "-"
    http_parts = []
    for check in result.http_checks:
        scheme = urlparse(check.url).scheme
        http_parts.append(f"{scheme}:{check.status if check.ok else 'ERR'}")
    print(
        f"[{result.verdict}] {result.host} score={result.passed_checks}/{result.total_checks} "
        f"fail={result.failed_checks} dns={result.dns_ok} ips={','.join(result.resolved_ips) or '-'} "
        f"tcp_ok={tcp_ok} {' '.join(http_parts)}"
    )


def main() -> int:
    args = parse_args()
    if not args.output:
        input_path = Path(args.input).resolve()
        args.output = str(
            input_path.parent
            / time.strftime("collaborator-health-results-%Y%m%d-%H%M%S.csv")
        )
        args.format = "csv"

    ports = [int(part.strip()) for part in args.ports.split(",") if part.strip()]
    inputs = load_inputs(args.input, args.column, args.delimiter)
    if not inputs:
        print("No inputs found.", file=sys.stderr)
        return 1

    results: list[CollaboratorHealthResult] = []
    output_handle = None
    csv_writer = None
    if args.output:
        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        args.output = str(output_path)
        print(f"Writing results to {args.output}")
        if args.format == "csv":
            output_handle = output_path.open("w", encoding="utf-8-sig", newline="")
            csv_writer = csv.DictWriter(
                output_handle,
                fieldnames=collaborator_csv_fieldnames(ports),
            )
            csv_writer.writeheader()
            output_handle.flush()

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
        future_map = {
            executor.submit(
                check_one,
                input_value,
                ports,
                args.timeout,
                args.proxy,
                args.verify_tls,
                args.max_fail,
            ): input_value
            for input_value in inputs
        }
        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            print_summary(result)
            if args.jsonl:
                print(json.dumps(asdict(result), ensure_ascii=False))
            if csv_writer and output_handle:
                csv_writer.writerow(flatten_for_csv(result))
                output_handle.flush()

    results.sort(key=lambda item: item.host)
    if output_handle:
        output_handle.close()
    elif args.output:
        export_results(args.output, args.format, results)
    print(f"Saved results to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
