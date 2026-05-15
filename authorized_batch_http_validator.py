#!/usr/bin/env python3
"""
Authorized batch HTTP/HTTPS validator.

This tool is intended for systems you own or are explicitly authorized to test.
It performs benign checks only:
  - normalizes inputs from txt/csv
  - optional DNS resolution
  - HTTP/HTTPS GET or HEAD probes
  - multithreaded execution
  - CSV/JSON/JSONL export

It does not generate exploit payloads or attempt callback exploitation.
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import requests


DEFAULT_TIMEOUT = 8.0
DEFAULT_THREADS = 16
DEFAULT_USER_AGENT = "AuthorizedBatchHttpValidator/1.0"


@dataclass
class TargetResult:
    input_value: str
    normalized_url: str
    scheme: str
    host: str
    dns_ok: bool
    resolved_ips: list[str]
    probe_ok: bool
    http_status: int | None
    final_url: str | None
    elapsed_ms: int | None
    content_type: str | None
    server: str | None
    title: str | None
    error: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Multithreaded allowlist-only HTTP/HTTPS batch validator."
    )
    parser.add_argument("-i", "--input", required=True, help="Input txt/csv file.")
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path. Default: auto-generated CSV next to this script.",
    )
    parser.add_argument(
        "--format",
        choices=("csv", "json", "jsonl"),
        default="csv",
        help="Export format when --output is set.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Worker threads. Default: {DEFAULT_THREADS}",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-request timeout in seconds. Default: {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--scheme",
        choices=("http", "https", "auto"),
        default="auto",
        help="Scheme to use when input has no scheme. Default: auto.",
    )
    parser.add_argument(
        "--method",
        choices=("GET", "HEAD"),
        default="GET",
        help="HTTP method to use. Default: GET.",
    )
    parser.add_argument(
        "--column",
        type=int,
        default=0,
        help="CSV column index to read when input is CSV. Default: 0.",
    )
    parser.add_argument(
        "--delimiter",
        default=",",
        help="CSV delimiter when input is CSV. Default: comma.",
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="User-Agent header value.",
    )
    parser.add_argument(
        "--proxy",
        help="Optional HTTP(S) proxy, e.g. http://127.0.0.1:8080",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify TLS certificates. Disabled by default for internal labs.",
    )
    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="Print JSONL to stdout in addition to any export file.",
    )
    return parser.parse_args()


def load_inputs(path: str, column: int, delimiter: str) -> list[str]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(path)

    values: list[str] = []
    if file_path.suffix.lower() == ".csv":
        with file_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, delimiter=delimiter)
            for row in reader:
                if not row:
                    continue
                if column >= len(row):
                    continue
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
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped


def normalize_target(raw_value: str, default_scheme: str) -> tuple[str, str, str]:
    value = raw_value.strip()
    if not value:
        raise ValueError("empty input")

    if not value.startswith(("http://", "https://")):
        if default_scheme == "auto":
            value = "https://" + value
        else:
            value = f"{default_scheme}://{value}"

    parsed = urlparse(value)
    if not parsed.netloc:
        raise ValueError(f"invalid target: {raw_value}")

    host = parsed.hostname or parsed.netloc
    return value, parsed.scheme, host


def resolve_dns(host: str) -> tuple[bool, list[str]]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False, []

    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return True, ips


def make_session(user_agent: str, proxy: str | None, verify_tls: bool) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": user_agent,
            "Accept": "*/*",
            "Connection": "close",
        }
    )
    session.verify = verify_tls
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


def extract_title(body: str) -> str | None:
    lower = body.lower()
    start = lower.find("<title>")
    end = lower.find("</title>")
    if start == -1 or end == -1 or end <= start + 7:
        return None
    return body[start + 7 : end].strip()[:200] or None


def probe_target(
    raw_value: str,
    default_scheme: str,
    method: str,
    timeout: float,
    user_agent: str,
    proxy: str | None,
    verify_tls: bool,
) -> TargetResult:
    normalized_url, scheme, host = normalize_target(raw_value, default_scheme)
    dns_ok, resolved_ips = resolve_dns(host)
    session = make_session(user_agent, proxy, verify_tls)

    start = time.perf_counter()
    try:
        response = session.request(
            method=method,
            url=normalized_url,
            timeout=timeout,
            allow_redirects=True,
        )
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        body = response.text if method == "GET" else ""
        return TargetResult(
            input_value=raw_value,
            normalized_url=normalized_url,
            scheme=scheme,
            host=host,
            dns_ok=dns_ok,
            resolved_ips=resolved_ips,
            probe_ok=True,
            http_status=response.status_code,
            final_url=str(response.url),
            elapsed_ms=elapsed_ms,
            content_type=response.headers.get("Content-Type"),
            server=response.headers.get("Server"),
            title=extract_title(body) if body else None,
            error=None,
        )
    except requests.RequestException as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return TargetResult(
            input_value=raw_value,
            normalized_url=normalized_url,
            scheme=scheme,
            host=host,
            dns_ok=dns_ok,
            resolved_ips=resolved_ips,
            probe_ok=False,
            http_status=None,
            final_url=None,
            elapsed_ms=elapsed_ms,
            content_type=None,
            server=None,
            title=None,
            error=str(exc),
        )


def export_csv(path: str, results: Iterable[TargetResult]) -> None:
    fieldnames = list(asdict(next(iter([TargetResult("", "", "", "", False, [], False, None, None, None, None, None, None)]))).keys())
    rows = [asdict(result) for result in results]
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            row["resolved_ips"] = "|".join(row["resolved_ips"])
            writer.writerow(row)


def http_csv_fieldnames() -> list[str]:
    return list(
        asdict(
            TargetResult("", "", "", "", False, [], False, None, None, None, None, None, None)
        ).keys()
    )


def http_csv_row(result: TargetResult) -> dict[str, object]:
    row = asdict(result)
    row["resolved_ips"] = "|".join(row["resolved_ips"])
    return row


def export_json(path: str, results: Iterable[TargetResult], jsonl: bool) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for result in results:
            payload = asdict(result)
            if jsonl:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
            else:
                handle.write(json.dumps(payload, ensure_ascii=False, indent=2))


def print_text(result: TargetResult) -> None:
    state = "OK" if result.probe_ok else "FAIL"
    print(f"[{state}] {result.input_value} -> {result.normalized_url}")
    print(
        f"  dns={result.dns_ok} ips={','.join(result.resolved_ips) or '-'} "
        f"status={result.http_status or '-'} elapsed_ms={result.elapsed_ms or '-'}"
    )
    if result.title:
        print(f"  title={result.title}")
    if result.server:
        print(f"  server={result.server}")
    if result.error:
        print(f"  error={result.error}")


def main() -> int:
    args = parse_args()
    if not args.output:
        input_path = Path(args.input).resolve()
        args.output = str(
            input_path.parent
            / time.strftime("authorized-http-results-%Y%m%d-%H%M%S.csv")
        )
        args.format = "csv"

    inputs = load_inputs(args.input, args.column, args.delimiter)
    if not inputs:
        print("No inputs found.", file=sys.stderr)
        return 1

    results: list[TargetResult] = []
    output_handle = None
    csv_writer = None
    if args.output:
        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        args.output = str(output_path)
        print(f"Writing results to {args.output}")
        if args.format == "csv":
            output_handle = output_path.open("w", encoding="utf-8-sig", newline="")
            csv_writer = csv.DictWriter(output_handle, fieldnames=http_csv_fieldnames())
            csv_writer.writeheader()
            output_handle.flush()

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
        future_map = {
            executor.submit(
                probe_target,
                raw_value,
                args.scheme,
                args.method,
                args.timeout,
                args.user_agent,
                args.proxy,
                args.verify_tls,
            ): raw_value
            for raw_value in inputs
        }
        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            print_text(result)
            if args.jsonl:
                print(json.dumps(asdict(result), ensure_ascii=False))
            if csv_writer and output_handle:
                csv_writer.writerow(http_csv_row(result))
                output_handle.flush()

    results.sort(key=lambda item: item.input_value)

    if output_handle:
        output_handle.close()
    elif args.output:
        output_path = Path(args.output)
        if args.format == "csv":
            export_csv(str(output_path), results)
        elif args.format == "json":
            export_json(str(output_path), results, jsonl=False)
        else:
            export_json(str(output_path), results, jsonl=True)
    print(f"Saved results to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
