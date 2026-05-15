# Authorized Batch HTTP Validator

This folder contains allowlist-only validators for assets you own or are explicitly authorized to test.

## HTTP Validator

`authorized_batch_http_validator.py` is useful for checking whether a list of internal endpoints or approved callback/collaboration servers are reachable.

## Usage

TXT input:

```bash
python authorized_batch_http_validator.py -i targets.txt
```

If `-o` is omitted, the CSV is saved in the same folder as `targets.txt`.

CSV input, reading column 0:

```bash
python authorized_batch_http_validator.py -i targets.csv --column 0 -o results.jsonl --format jsonl --threads 16
```

Force HTTP instead of HTTPS when inputs have no scheme:

```bash
python authorized_batch_http_validator.py -i targets.txt --scheme http -o results.csv
```

Use a proxy:

```bash
python authorized_batch_http_validator.py -i targets.txt --proxy http://127.0.0.1:8080 -o results.csv
```

## Output Fields

- `input_value`: original input value
- `normalized_url`: probed URL
- `dns_ok`: whether DNS resolution worked
- `resolved_ips`: resolved IP list
- `probe_ok`: whether HTTP/HTTPS probe completed
- `http_status`: HTTP status code
- `final_url`: final URL after redirects
- `elapsed_ms`: probe time
- `content_type`, `server`, `title`: basic response metadata
- `error`: request error if any

## Scope Boundary

Do not use this with blind third-party FOFA/Shodan lists. Use only with approved targets.

## Collaborator/OAST Health Checker

`authorized_collaborator_healthcheck.py` checks connectivity for approved Collaborator/OAST-style servers:

- DNS resolution
- TCP ports `53,80,443,25,587,465` by default
- HTTP and HTTPS basic responses
- SMTP/SMTPS banner/connectivity where available

Example:

```bash
python authorized_collaborator_healthcheck.py -i collaborators.txt
```

If `-o` is omitted, the CSV is saved in the same folder as `collaborators.txt`.

Default verdict logic:

- `PASS`: all checks passed
- `PASS_WITH_WARNINGS`: one or two checks failed
- `FAIL`: more than two checks failed

Change tolerance:

```bash
python authorized_collaborator_healthcheck.py -i collaborators.txt --max-fail 1
```

Custom ports:

```bash
python authorized_collaborator_healthcheck.py -i collaborators.txt --ports 53,80,443 -o collaborator-results.jsonl --format jsonl
```

Important: this only proves network connectivity. It cannot prove that a third-party server will return interaction records to your Burp client. For reliable testing, use Burp's official Collaborator service or a private server you control.
