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
    polling_host: str
    polling_dns_ok: bool
    polling_resolved_ips: list[str]
    tcp_checks: list[PortCheck]
    http_checks: list[HttpCheck]
    polling_http_checks: list[HttpCheck]
    passed_checks: int
    total_checks: int
    failed_checks: int
    pass_rate: float
    all_checks_ok: bool
    failed_check_names: list[str]
    verdict: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="仅用于白名单目标的多线程 Collaborator/OAST 健康检查器。"
    )
    parser.add_argument("-i", "--input", required=True, help="TXT/CSV 白名单输入文件。")
    parser.add_argument("-o", "--output", help="导出路径。不填则自动生成 CSV。")
    parser.add_argument(
        "--format",
        choices=("csv", "json", "jsonl"),
        default="csv",
        help="导出格式。默认：csv",
    )
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        help=f"逗号分隔的 TCP 端口。默认：{DEFAULT_PORTS}",
    )
    parser.add_argument("--column", type=int, default=0, help="CSV 列索引。")
    parser.add_argument("--delimiter", default=",", help="CSV 分隔符。")
    parser.add_argument("--proxy", help="可选的 HTTP/S 代理。")
    parser.add_argument("--verify-tls", action="store_true")
    parser.add_argument("--jsonl", action="store_true", help="同时输出 JSONL。")
    parser.add_argument(
        "--max-fail",
        type=int,
        default=2,
        help="仍视为“通过但有警告”的最大失败项数。默认：2",
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


def build_polling_host(host: str) -> str:
    if not host:
        return ""
    if host.startswith("polling."):
        return host
    return f"polling.{host}"


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
    polling_dns_ok: bool,
    tcp_checks: list[PortCheck],
    http_checks: list[HttpCheck],
    polling_http_checks: list[HttpCheck],
    max_fail: int,
) -> tuple[int, int, int, float, bool, list[str], str]:
    failed_check_names: list[str] = []
    if not dns_ok:
        failed_check_names.append("dns")
    if not polling_dns_ok:
        failed_check_names.append("polling_dns")
    for check in tcp_checks:
        if not check.ok:
            failed_check_names.append(f"tcp:{check.port}")
    for check in http_checks:
        if not check.ok:
            failed_check_names.append(urlparse(check.url).scheme)
    for check in polling_http_checks:
        if not check.ok:
            failed_check_names.append(f"polling_{urlparse(check.url).scheme}")

    passed_checks = 1 if dns_ok else 0
    total_checks = 1

    passed_checks += 1 if polling_dns_ok else 0
    total_checks += 1

    passed_checks += sum(1 for check in tcp_checks if check.ok)
    total_checks += len(tcp_checks)

    passed_checks += sum(1 for check in http_checks if check.ok)
    total_checks += len(http_checks)

    passed_checks += sum(1 for check in polling_http_checks if check.ok)
    total_checks += len(polling_http_checks)

    failed_checks = len(failed_check_names)
    pass_rate = round((passed_checks / total_checks) * 100, 2) if total_checks else 0.0
    all_checks_ok = failed_checks == 0

    if failed_checks == 0:
        verdict = "PASS"
    elif failed_checks <= max_fail:
        verdict = "PASS_WITH_WARNINGS"
    else:
        verdict = "FAIL"
    return passed_checks, total_checks, failed_checks, pass_rate, all_checks_ok, failed_check_names, verdict


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
    polling_host = build_polling_host(host)
    polling_dns_ok, polling_ips = resolve_host(polling_host)
    tcp_checks = [tcp_check(host, port, timeout) for port in ports]
    http_checks = [
        http_check(host, "http", timeout, proxy, verify_tls),
        http_check(host, "https", timeout, proxy, verify_tls),
    ]
    polling_http_checks = [
        http_check(polling_host, "http", timeout, proxy, verify_tls),
        http_check(polling_host, "https", timeout, proxy, verify_tls),
    ]
    passed_checks, total_checks, failed_checks, pass_rate, all_checks_ok, failed_check_names, verdict = score_result(
        dns_ok,
        polling_dns_ok,
        tcp_checks,
        http_checks,
        polling_http_checks,
        max_fail,
    )
    return CollaboratorHealthResult(
        input_value=input_value,
        host=host,
        dns_ok=dns_ok,
        resolved_ips=ips,
        polling_host=polling_host,
        polling_dns_ok=polling_dns_ok,
        polling_resolved_ips=polling_ips,
        tcp_checks=tcp_checks,
        http_checks=http_checks,
        polling_http_checks=polling_http_checks,
        passed_checks=passed_checks,
        total_checks=total_checks,
        failed_checks=failed_checks,
        pass_rate=pass_rate,
        all_checks_ok=all_checks_ok,
        failed_check_names=failed_check_names,
        verdict=verdict,
    )


def flatten_for_csv(result: CollaboratorHealthResult) -> dict[str, str]:
    row: dict[str, str] = {
        "输入值": result.input_value,
        "主机": result.host,
        "结论": verdict_label(result.verdict),
        "通过项数": str(result.passed_checks),
        "总项数": str(result.total_checks),
        "失败项数": str(result.failed_checks),
        "通过率(%)": str(result.pass_rate),
        "全绿": str(result.all_checks_ok),
        "失败项列表": "|".join(result.failed_check_names),
        "DNS成功": str(result.dns_ok),
        "解析IP列表": "|".join(result.resolved_ips),
        "Polling主机": result.polling_host,
        "Polling DNS成功": str(result.polling_dns_ok),
        "Polling解析IP列表": "|".join(result.polling_resolved_ips),
    }
    for check in result.tcp_checks:
        prefix = f"端口{check.port}"
        row[f"{prefix}成功"] = str(check.ok)
        row[f"{prefix}耗时毫秒"] = str(check.elapsed_ms)
        row[f"{prefix}Banner"] = check.banner or ""
        row[f"{prefix}错误"] = check.error or ""
    for check in result.http_checks:
        scheme = urlparse(check.url).scheme
        prefix = "HTTP" if scheme == "http" else "HTTPS"
        row[f"{prefix}成功"] = str(check.ok)
        row[f"{prefix}状态码"] = str(check.status or "")
        row[f"{prefix}耗时毫秒"] = str(check.elapsed_ms)
        row[f"{prefix}服务器"] = check.server or ""
        row[f"{prefix}标题"] = check.title or ""
        row[f"{prefix}错误"] = check.error or ""
    for check in result.polling_http_checks:
        scheme = urlparse(check.url).scheme
        prefix = "Polling HTTP" if scheme == "http" else "Polling HTTPS"
        row[f"{prefix}成功"] = str(check.ok)
        row[f"{prefix}状态码"] = str(check.status or "")
        row[f"{prefix}耗时毫秒"] = str(check.elapsed_ms)
        row[f"{prefix}服务器"] = check.server or ""
        row[f"{prefix}标题"] = check.title or ""
        row[f"{prefix}错误"] = check.error or ""
    return row


def verdict_label(verdict: str) -> str:
    mapping = {
        "PASS": "通过",
        "PASS_WITH_WARNINGS": "通过但有警告",
        "FAIL": "失败",
    }
    return mapping.get(verdict, verdict)


def collaborator_csv_fieldnames(ports: list[int]) -> list[str]:
    fieldnames = [
        "输入值",
        "主机",
        "结论",
        "通过项数",
        "总项数",
        "失败项数",
        "通过率(%)",
        "全绿",
        "失败项列表",
        "DNS成功",
        "解析IP列表",
        "Polling主机",
        "Polling DNS成功",
        "Polling解析IP列表",
    ]
    for port in ports:
        prefix = f"端口{port}"
        fieldnames.extend(
            [
                f"{prefix}成功",
                f"{prefix}耗时毫秒",
                f"{prefix}Banner",
                f"{prefix}错误",
            ]
        )
    for scheme in ("http", "https"):
        prefix = "HTTP" if scheme == "http" else "HTTPS"
        fieldnames.extend(
            [
                f"{prefix}成功",
                f"{prefix}状态码",
                f"{prefix}耗时毫秒",
                f"{prefix}服务器",
                f"{prefix}标题",
                f"{prefix}错误",
            ]
        )
    for scheme in ("http", "https"):
        prefix = "Polling HTTP" if scheme == "http" else "Polling HTTPS"
        fieldnames.extend(
            [
                f"{prefix}成功",
                f"{prefix}状态码",
                f"{prefix}耗时毫秒",
                f"{prefix}服务器",
                f"{prefix}标题",
                f"{prefix}错误",
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
    failed = ",".join(result.failed_check_names) or "-"
    print(
        f"[{verdict_label(result.verdict)}] {result.host} 全绿={result.all_checks_ok} "
        f"得分={result.passed_checks}/{result.total_checks} 失败={result.failed_checks} "
        f"DNS={result.dns_ok} IP={','.join(result.resolved_ips) or '-'} "
        f"TCP通过={tcp_ok} 失败项={failed} {' '.join(http_parts)}"
    )


def print_batch_summary(results: list[CollaboratorHealthResult]) -> None:
    total = len(results)
    pass_count = sum(1 for result in results if result.verdict == "PASS")
    warn_count = sum(1 for result in results if result.verdict == "PASS_WITH_WARNINGS")
    fail_count = sum(1 for result in results if result.verdict == "FAIL")
    full_green = sum(1 for result in results if result.all_checks_ok)
    print("汇总结果")
    print(f"  总数: {total}")
    print(f"  全绿: {full_green}")
    print(f"  通过: {pass_count}")
    print(f"  通过但有警告: {warn_count}")
    print(f"  失败: {fail_count}")


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
        print("未找到输入。", file=sys.stderr)
        return 1

    results: list[CollaboratorHealthResult] = []
    output_handle = None
    csv_writer = None
    if args.output:
        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        args.output = str(output_path)
        print(f"正在写入结果：{args.output}")
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
    print_batch_summary(results)
    print(f"结果已保存到：{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
