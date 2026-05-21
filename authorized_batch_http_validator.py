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
    all_ok: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="仅用于白名单目标的多线程 HTTP/HTTPS 批量验证器。"
    )
    parser.add_argument("-i", "--input", required=True, help="TXT/CSV 输入文件。")
    parser.add_argument(
        "-o",
        "--output",
        help="输出文件路径。不填则在输入文件旁自动生成 CSV。",
    )
    parser.add_argument(
        "--format",
        choices=("csv", "json", "jsonl"),
        default="csv",
        help="输出格式。",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"工作线程数。默认：{DEFAULT_THREADS}",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"单次请求超时（秒）。默认：{DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--scheme",
        choices=("http", "https", "auto"),
        default="auto",
        help="输入没有 scheme 时使用的协议。默认：auto。",
    )
    parser.add_argument(
        "--method",
        choices=("GET", "HEAD"),
        default="GET",
        help="HTTP 方法。默认：GET。",
    )
    parser.add_argument(
        "--column",
        type=int,
        default=0,
        help="输入为 CSV 时读取的列索引。默认：0。",
    )
    parser.add_argument(
        "--delimiter",
        default=",",
        help="输入为 CSV 时的分隔符。默认：逗号。",
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="User-Agent 头值。",
    )
    parser.add_argument(
        "--proxy",
        help="可选 HTTP(S) 代理，例如 http://127.0.0.1:8080",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="验证 TLS 证书。默认关闭。",
    )
    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="除导出文件外，同时在标准输出打印 JSONL。",
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
            all_ok=dns_ok and response.ok,
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
            all_ok=False,
        )


def export_csv(path: str, results: Iterable[TargetResult]) -> None:
    fieldnames = http_csv_fieldnames()
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(http_csv_row(result))


def http_csv_fieldnames() -> list[str]:
    return [
        "输入值",
        "规范化URL",
        "协议",
        "主机",
        "DNS成功",
        "解析IP列表",
        "探测成功",
        "HTTP状态码",
        "最终URL",
        "耗时毫秒",
        "内容类型",
        "服务器",
        "标题",
        "错误",
        "全绿",
    ]


def http_csv_row(result: TargetResult) -> dict[str, object]:
    return {
        "输入值": result.input_value,
        "规范化URL": result.normalized_url,
        "协议": result.scheme,
        "主机": result.host,
        "DNS成功": result.dns_ok,
        "解析IP列表": "|".join(result.resolved_ips),
        "探测成功": result.probe_ok,
        "HTTP状态码": result.http_status if result.http_status is not None else "",
        "最终URL": result.final_url or "",
        "耗时毫秒": result.elapsed_ms if result.elapsed_ms is not None else "",
        "内容类型": result.content_type or "",
        "服务器": result.server or "",
        "标题": result.title or "",
        "错误": result.error or "",
        "全绿": result.all_ok,
    }


def export_json(path: str, results: Iterable[TargetResult], jsonl: bool) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for result in results:
            payload = asdict(result)
            if jsonl:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
            else:
                handle.write(json.dumps(payload, ensure_ascii=False, indent=2))


def print_text(result: TargetResult) -> None:
    state = "成功" if result.probe_ok else "失败"
    print(f"[{state}] {result.input_value} -> {result.normalized_url} 全绿={result.all_ok}")
    print(
        f"  DNS={result.dns_ok} IP={','.join(result.resolved_ips) or '-'} "
        f"状态={result.http_status or '-'} 耗时={result.elapsed_ms or '-'}ms"
    )
    if result.title:
        print(f"  标题={result.title}")
    if result.server:
        print(f"  服务器={result.server}")
    if result.error:
        print(f"  错误={result.error}")


def print_batch_summary(results: list[TargetResult]) -> None:
    total = len(results)
    success_count = sum(1 for result in results if result.probe_ok)
    fail_count = total - success_count
    full_green = sum(1 for result in results if result.all_ok)
    print("汇总结果")
    print(f"  总数: {total}")
    print(f"  全绿: {full_green}")
    print(f"  成功: {success_count}")
    print(f"  失败: {fail_count}")


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
        print("未找到输入。", file=sys.stderr)
        return 1

    results: list[TargetResult] = []
    output_handle = None
    csv_writer = None
    if args.output:
        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        args.output = str(output_path)
        print(f"正在写入结果：{args.output}")
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
    print_batch_summary(results)
    print(f"结果已保存到：{args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
