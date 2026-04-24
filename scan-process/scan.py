#!/usr/bin/env python3
import argparse
import base64
import json
import os
import re
import sys
from datetime import datetime

REPORT_DIR = "scan-report"

import paramiko
import requests
import yaml

ANSI_RESET = "\033[0m"
ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_GREEN = "\033[92m"
ANSI_BOLD = "\033[1m"

KNOWN_MINERS = {"xmrig", "minerd", "cpuminer", "ethminer", "nbminer", "lolminer", "cgminer", "bfgminer"}
SUSPICIOUS_PATHS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/")
COMMON_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                3306, 5432, 6379, 8080, 8443, 9200, 27017}
RANDOM_HEX_RE = re.compile(r"^[a-f0-9]{8,}$")
CPU_HIGH_THRESHOLD = 80.0

# Remote Python script that measures real-time CPU% via two /proc/stat snapshots
# (1-second interval). Encoded as base64 to avoid shell-quoting issues.
_CPU_SCRIPT = b"""
import time, glob, re

def T():
    return sum(int(x) for x in open('/proc/stat').readline().split()[1:])

def P():
    r = {}
    for f in glob.glob('/proc/[0-9]*/stat'):
        try:
            d = open(f).read()
            m = re.match(r'(\\d+) \\(.*?\\) \\S+ \\S+ \\S+ \\S+ \\S+ \\S+ \\S+ \\S+ \\S+ \\S+ \\S+ (\\d+) (\\d+)', d)
            if m:
                r[m.group(1)] = int(m.group(2)) + int(m.group(3))
        except:
            pass
    return r

t1, s1 = T(), P()
time.sleep(1)
t2, s2 = T(), P()
dt = t2 - t1
if dt > 0:
    for p in s2:
        dp = s2[p] - s1.get(p, s2[p])
        pct = dp / dt * 100
        if pct > 0.5:
            print(p, round(pct, 1), sep='\\t')
"""

CPU_SAMPLE_CMD = (
    "echo " + base64.b64encode(_CPU_SCRIPT).decode() + " | base64 -d | python3 2>/dev/null"
)

REMOTE_COMMANDS = [
    "ps aux --no-headers 2>/dev/null",
    "ls -la /proc/*/exe 2>/dev/null | grep -i deleted || true",
    "ls -la /proc/*/exe 2>/dev/null | grep -E '/tmp|/dev/shm|/var/tmp|/run/shm' || true",
    "ss -tnpu 2>/dev/null || netstat -tnpu 2>/dev/null || true",
]


def color(text, code):
    return f"{code}{text}{ANSI_RESET}"


def load_config(path):
    with open(path) as f:
        data = yaml.safe_load(f)
    machines = data.get("machines", [])
    validated = []
    for i, m in enumerate(machines):
        for field in ("ip", "username", "password"):
            if field not in m:
                print(color(f"[SKIP] Machine #{i+1} missing '{field}' field", ANSI_YELLOW))
                break
        else:
            m.setdefault("port", 22)
            m.setdefault("label", m["ip"])
            validated.append(m)
    return {
        "machines": validated,
        "slack_webhook_url": data.get("slack_webhook_url"),
        "slack_alert_severity": data.get("slack_alert_severity", ["CRITICAL", "HIGH", "MEDIUM"]),
    }


def ssh_exec(client, cmd):
    _, stdout, _ = client.exec_command(cmd, timeout=30)
    return stdout.read().decode(errors="replace")


def collect_remote_data(client):
    data = {cmd: ssh_exec(client, cmd) for cmd in REMOTE_COMMANDS}
    data["cpu_sample"] = ssh_exec(client, CPU_SAMPLE_CMD)
    return data


def parse_ps_line(line):
    parts = line.split(None, 10)
    if len(parts) < 11:
        return None
    return {
        "user": parts[0],
        "pid": parts[1],
        "cpu": parts[2],
        "mem": parts[3],
        "cmd": parts[10].strip(),
        "name": parts[10].strip().split()[0].split("/")[-1] if parts[10].strip() else "",
    }


def parse_realtime_cpu(cpu_output: str, ps_by_pid: dict, threshold: float = CPU_HIGH_THRESHOLD) -> list:
    findings = []
    for line in cpu_output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        pid, cpu_str = parts
        try:
            cpu_pct = float(cpu_str)
        except ValueError:
            continue
        if cpu_pct >= threshold:
            proc = ps_by_pid.get(pid, {})
            findings.append({
                "pid": pid,
                "name": proc.get("name", "?"),
                "user": proc.get("user", "?"),
                "cpu": cpu_str,
                "cmd": proc.get("cmd", "?"),
                "reason": f"Real-time CPU usage: {cpu_pct}%",
                "severity": "MEDIUM",
            })
    return findings


def detect_suspicious(data):
    findings = []
    ps_output = data.get(REMOTE_COMMANDS[0], "")
    deleted_output = data.get(REMOTE_COMMANDS[1], "")
    suspicious_path_output = data.get(REMOTE_COMMANDS[2], "")
    ss_output = data.get(REMOTE_COMMANDS[3], "")
    cpu_output = data.get("cpu_sample", "")

    ps_by_pid = {}
    for line in ps_output.splitlines():
        proc = parse_ps_line(line)
        if proc:
            ps_by_pid[proc["pid"]] = proc

    for line in ps_output.splitlines():
        proc = parse_ps_line(line)
        if not proc:
            continue
        name = proc["name"]
        cmd = proc["cmd"]

        if name.lower() in KNOWN_MINERS or any(m in cmd.lower() for m in KNOWN_MINERS):
            findings.append({**proc, "reason": "Known crypto miner process", "severity": "CRITICAL"})
            continue

        if RANDOM_HEX_RE.match(name):
            findings.append({**proc, "reason": "Process name looks like random hex string", "severity": "MEDIUM"})

    findings.extend(parse_realtime_cpu(cpu_output, ps_by_pid))

    for line in deleted_output.splitlines():
        line = line.strip()
        if not line:
            continue
        pid_match = re.search(r"/proc/(\d+)/exe", line)
        pid = pid_match.group(1) if pid_match else "?"
        findings.append({
            "pid": pid, "name": "?", "user": "?", "cpu": "?", "cmd": line,
            "reason": "Process binary has been deleted (possible fileless malware)", "severity": "HIGH"
        })

    for line in suspicious_path_output.splitlines():
        line = line.strip()
        if not line:
            continue
        path_match = re.search(r"-> (.+)$", line)
        path = path_match.group(1) if path_match else line
        if any(sp in path for sp in SUSPICIOUS_PATHS):
            pid_match = re.search(r"/proc/(\d+)/exe", line)
            pid = pid_match.group(1) if pid_match else "?"
            findings.append({
                "pid": pid, "name": path.split("/")[-1], "user": "?", "cpu": "?", "cmd": path,
                "reason": f"Binary running from suspicious path: {path}", "severity": "HIGH"
            })

    for line in ss_output.splitlines():
        port_match = re.search(r":(\d+)\s", line)
        if not port_match:
            continue
        port = int(port_match.group(1))
        if port > 1024 and port not in COMMON_PORTS and ("LISTEN" in line or "ESTABLISHED" in line):
            proc_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            name = proc_match.group(1) if proc_match else "?"
            pid = proc_match.group(2) if proc_match else "?"
            findings.append({
                "pid": pid, "name": name, "user": "?", "cpu": "?", "cmd": line.strip(),
                "reason": f"Process listening on unusual port {port}", "severity": "LOW"
            })

    seen = set()
    unique = []
    for f in findings:
        key = (f["pid"], f["reason"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def severity_color(sev):
    return {
        "CRITICAL": ANSI_RED,
        "HIGH": ANSI_RED,
        "MEDIUM": ANSI_YELLOW,
        "LOW": ANSI_YELLOW,
    }.get(sev, ANSI_RESET)


def print_machine_header(machine):
    print(f"\n{ANSI_BOLD}{'='*60}{ANSI_RESET}")
    print(f"{ANSI_BOLD}  {machine['label']} ({machine['ip']}){ANSI_RESET}")
    print(f"{ANSI_BOLD}{'='*60}{ANSI_RESET}")


def print_findings(findings):
    if not findings:
        print(color("  [OK] No suspicious processes detected.", ANSI_GREEN))
        return
    for f in findings:
        sev = f.get("severity", "?")
        c = severity_color(sev)
        print(color(f"  [{sev}]", c) + f" PID={f['pid']} NAME={f['name']} USER={f['user']} CPU={f['cpu']}%")
        print(f"         Reason : {f['reason']}")
        if f.get("cmd") and f["cmd"] != f["name"]:
            cmd_preview = f["cmd"][:120] + ("..." if len(f["cmd"]) > 120 else "")
            print(f"         Command: {cmd_preview}")


def send_slack_alert(
    webhook_url: str,
    severity_filter: list,
    scan_time: datetime,
    machines_report: list,
) -> None:
    severity_set = set(severity_filter)
    affected = []
    for machine in machines_report:
        filtered = [
            f for f in machine.get("suspicious_processes", [])
            if f.get("severity") in severity_set
        ]
        if filtered:
            affected.append({"machine": machine, "findings": filtered})

    if not affected:
        return

    total_findings = sum(len(a["findings"]) for a in affected)

    def attachment_color(findings):
        sevs = {f["severity"] for f in findings}
        if "CRITICAL" in sevs or "HIGH" in sevs:
            return "#E03E2D"
        if "MEDIUM" in sevs:
            return "#F0A500"
        return "#808080"

    attachments = []
    for a in affected:
        machine = a["machine"]
        findings = a["findings"]
        lines = [
            f"[{f.get('severity','?')}] PID={f.get('pid','?')}  {f.get('name','?')}  —  {f.get('reason','?')}"
            for f in findings
        ]
        attachments.append({
            "color": attachment_color(findings),
            "title": f"{machine['label']} ({machine['ip']}) — {len(findings)} finding(s)",
            "text": "\n".join(lines),
            "mrkdwn_in": ["text"],
        })

    payload = {
        "text": (
            f":rotating_light: *SCAN ALERT* — {scan_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"{len(affected)} machine(s) affected, {total_findings} total finding(s)"
        ),
        "attachments": attachments,
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        print(color(f"\n  [Slack] Alert sent ({len(affected)} machine(s) reported)", ANSI_GREEN))
    except requests.RequestException as e:
        print(color(f"\n  [WARN] Slack alert failed: {e}", ANSI_YELLOW))


def scan_machine(machine, verbose=False):
    ip = machine["ip"]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=machine["port"], username=machine["username"],
                       password=machine["password"], timeout=10)
    except Exception as e:
        return {"status": "connection_failed", "error": str(e), "suspicious_processes": []}

    try:
        data = collect_remote_data(client)
        if verbose:
            for cmd, out in data.items():
                label = cmd[:80] + ("..." if len(cmd) > 80 else "")
                print(color(f"\n  [CMD] {label}", ANSI_YELLOW))
                for line in out.splitlines()[:20]:
                    print(f"    {line}")
        findings = detect_suspicious(data)
        return {"status": "connected", "suspicious_processes": findings}
    except Exception as e:
        return {"status": "scan_failed", "error": str(e), "suspicious_processes": []}
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description="Remote suspicious process scanner")
    parser.add_argument("--config", default="config.yaml", help="Path to config YAML (default: config.yaml)")
    parser.add_argument("--output", default=None, help="Output JSON report path (auto-named if omitted)")
    parser.add_argument("--verbose", action="store_true", help="Print raw remote command output")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print(color(f"[ERROR] Config file not found: {args.config}", ANSI_RED))
        sys.exit(1)
    except yaml.YAMLError as e:
        print(color(f"[ERROR] Invalid YAML: {e}", ANSI_RED))
        sys.exit(1)

    machines = config["machines"]
    if not machines:
        print(color("[ERROR] No valid machines found in config.", ANSI_RED))
        sys.exit(1)

    scan_time = datetime.now()
    report = {"scan_time": scan_time.isoformat(), "machines": []}

    print(color(f"\nProcess Scanner — {scan_time.strftime('%Y-%m-%d %H:%M:%S')}", ANSI_BOLD))
    print(f"Scanning {len(machines)} machine(s)...\n")

    for machine in machines:
        print_machine_header(machine)
        print(f"  Connecting to {machine['ip']}:{machine['port']} as {machine['username']}...")
        result = scan_machine(machine, verbose=args.verbose)

        if result["status"] == "connection_failed":
            print(color(f"  [FAIL] Connection failed: {result.get('error', 'unknown')}", ANSI_RED))
        elif result["status"] == "scan_failed":
            print(color(f"  [FAIL] Scan error: {result.get('error', 'unknown')}", ANSI_RED))
        else:
            print_findings(result["suspicious_processes"])

        report["machines"].append({"ip": machine["ip"], "label": machine["label"], **result})

    os.makedirs(REPORT_DIR, exist_ok=True)
    default_filename = f"scan_report_{scan_time.strftime('%Y%m%d_%H%M%S')}.json"
    output_path = args.output or os.path.join(REPORT_DIR, default_filename)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    total = sum(len(m.get("suspicious_processes", [])) for m in report["machines"])
    print(f"\n{ANSI_BOLD}{'='*60}{ANSI_RESET}")
    print(f"Scan complete. Suspicious processes found: {color(str(total), ANSI_RED if total else ANSI_GREEN)}")
    print(f"Report saved to: {output_path}")

    webhook_url = config.get("slack_webhook_url")
    if webhook_url:
        send_slack_alert(
            webhook_url=webhook_url,
            severity_filter=config["slack_alert_severity"],
            scan_time=scan_time,
            machines_report=report["machines"],
        )


if __name__ == "__main__":
    main()
