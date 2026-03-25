from __future__ import annotations

import csv
import io
import os
import platform
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Tuple

from .model import CoverageNote

@dataclass
class ProcessInfo:
    pid: int
    ppid: int | None
    user: str | None
    name: str
    cmdline: str

@dataclass
class ListeningPort:
    local_addr: str
    port: int
    proto: str
    state: str

@dataclass
class AuthSignal:
    failed_logins: int
    raw_source: str


@dataclass
class Collection:
    processes: list[ProcessInfo]
    listeners: list[ListeningPort]
    auth_signal: AuthSignal | None
    sudoers_text: str | None
    world_writable: list[str]
    coverage: list[CoverageNote]

def _run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", "Command Not Found"

def _collect_processes() -> tuple[list[ProcessInfo], list[CoverageNote]]:
    coverage: list[CoverageNote] = []

    try:
        import psutil

        processes: list[ProcessInfo] = []
        for proc in psutil.process_iter(attrs=["pid", "ppid", "username", "name", "cmdline"]):
            info = proc.info
            cmdline = " ".join(info.get("cmdline") or [])
            processes.append(
                ProcessInfo(
                    pid = int(info.get("pid")),
                    ppid = info.get("ppid"),
                    user = info.get("username"),
                    name = info.get("name") or "",
                    cmdline = cmdline,
                )
            )
        return processes, coverage
    except Exception:
        coverage.append(CoverageNote("processes", "psutil unavailable; using os commands"))

    system = platform.system().lower()
    if system in {"linux", "darwin"}:
        code, out, err = _run(["ps", "-axo", "pid=,ppid=,user=,comm=,args="])
        if code !=0:
            coverage.append(CoverageNote("processes", f"ps failed: {err.strip()}"))
            return [], coverage
        processes = []
        for line in out.splitlines():
            if not line.strip():
                continue
            parts = line.strip().split(maxsplit=4)
            if len(parts) < 4:
                continue
            pid = int(parts[0])
            ppid = int(parts[1]) if parts[1].isdigit() else None
            user = parts[2]
            name = parts[3]
            cmdline = parts[4] if len(parts) > 4 else name
            processes.append(ProcessInfo(pid=pid, ppid= ppid, user= user, name = name, cmdline= cmdline))
        return processes, coverage

    if system == "windows":
        ps_cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Csv -NoTypeInformation",
            ]
        code, out, err = _run(ps_cmd)
        if code != 0:
            coverage.append(CoverageNote("processes", f"powershell failed: {err.strip()}"))
            return [], coverage
        reader = csv.DictReader(out.splitlines())
        processes = []
        for row in reader:
            try:
                pid = int(row.get("ProcessId", "0"))
            except ValueError:
                continue
            ppid_raw = row.get("ParentProcessId")
            ppid = int(ppid_raw) if ppid_raw and ppid_raw.isdigit() else None
            name = row.get("Name") or ""
            cmdline = row.get("CommandLine") or name
            processes.append(ProcessInfo(pid = pid, ppid = ppid, user = None, name = name, cmdline = cmdline))
        return processes, coverage

    coverage.append(CoverageNote("processes", f"unsupported os:{system}"))
    return [], coverage

def _parse_listening_line(line: str) -> ListeningPort | None:
    tokens = line.split()
    if len(tokens) < 4:
        return None
    proto = tokens[0].lower()
    state = tokens[-1].upper()
    if state not in {"LISTEN", "LISTENING"}:
        return None

    for idx in range(1, min(len(tokens), 5)):
        if ":" in tokens[idx] or "." in tokens[idx]:
            local = tokens[idx]
            break
    else:
        return None

    if local.count(":") >1 and local.startswith("[") and "]" in local:
        local = local.strip("[]")

    port_match = re.search(r":(\d+)$", local)
    if port_match:
        port = int(port_match.group(1))
        local_addr = local[: local.rfind(":")]
    else:
        port_match = re.search(r"\.(\d+)$", local)
        if not port_match:
            return None
        port = int(port_match.group(1))
        local_addr = local[: local.rfind(".")]
    return ListeningPort(local_addr=local_addr, port=port, proto=proto, state=state)

def _collect_listeners() -> tuple[list[ListeningPort], list[CoverageNote]]:
    coverage: list[CoverageNote] = []
    system = platform.system().lower()

    cmds: list[list[str]]  = []
    if system == "windows":
        cmds = [["netstat", "-ano"]]
    else:
        cmds = [["netstat", "-an"], ["ss", "-lntu"]]

    for cmd in cmds:
        code, out, err = _run(cmd)
        if code != 0:
            coverage.append(CoverageNote("network", f"{cmd[0]} failed: {err.strip()}"))
            continue
        listeners: list[ListeningPort] = []
        for line in out.splitlines():
            if "LISTEN" not in line.upper():
                continue
            parsed = _parse_listening_line(line)
            if parsed:
                listeners.append(parsed)
        if listeners:
            return listeners, coverage

    coverage.append(CoverageNote("network", "no listening ports parsed"))
    return [], coverage

def _collect_auth_signal() -> tuple[AuthSignal | None, list[CoverageNote]]:
    coverage: list[CoverageNote] = []
    system = platform.system().lower()

    log_candidates: list[Path] = []
    if system == "linux":
        log_candidates = [Path("/var/log/auth.log"), Path("/var/log/secure")]
    elif system == "darwin":
        log_candidates = [Path("/var/log/system.log")]

    for path in log_candidates:
        if not path.exists():
            continue
        try:
            data = path.read_text(errors="ignore")
        except PermissionError:
            coverage.append(CoverageNote("auth", f"permission denied {path}"))
            continue
        failed = len(re.findall(r"failed password|authentication failure|invalid user", data, re.IGNORECASE))
        return AuthSignal(failed_logins=failed, raw_source=str(path)), coverage

    if system == "windows":
        cmd= ["wevtutil", "qe", "Security", "/c:200", "/rd:true", "/f:text"]
        code, out, err = _run(cmd)
        if code != 0:
            coverage.append(CoverageNote("auth", f"wevtutil failed: {err.strip()}"))
            return None, coverage
        failed = len(re.findall(r"failed logon|failure", out, re.IGNORECASE))
        return AuthSignal(failed_logins=failed, raw_source="Windows Security Log"), coverage

    coverage.append(CoverageNote("auth", "no accessible authlogs"))
    return None, coverage


def _collect_sudoers() -> tuple[str | None, list[CoverageNote]]:
    coverage: list[CoverageNote] = []
    sudoers = Path("/etc/sudoers")
    if not sudoers.exists():
        return None, coverage
    try:
        return sudoers.read_text(errors="ignore"), coverage
    except PermissionError:
        coverage.append(CoverageNote("sudoers", "permission denied reading /etc/sudoers"))
        return None, coverage




def _collect_world_writable() -> tuple[list[str], list[CoverageNote]]:
    coverage: list[CoverageNote] = []
    system = platform.system().lower()
    if system not in {"linux", "darwin"}:
        coverage.append(CoverageNote("filesystem", "world-writable checks skipped on non-POSIX OS"))
        return [], coverage


    paths = [
        Path("/etc"),
        Path("/usr/local/bin"),
        Path("/usr/bin"),
        Path("/usr/sbin"),
        Path("/bin"),
        Path("/sbin")
    ]

    world_writable: list[str] = []
    for base in paths:
        if not base.exists():
            continue
        try:
            for item in base.iterdir():
                try:
                    mode = item.stat(follow_symlinks=False).st_mode
                except PermissionError:
                    continue
                if mode & 0o002:
                    world_writable.append(str(item))
        except PermissionError:
            coverage.append(CoverageNote("filesystem", f"permission denied reading {base}"))


    return world_writable, coverage

def collect_all() -> Collection:
    processes, proc_cov = _collect_processes()
    listeners, net_cov = _collect_listeners()
    auth_signal, auth_cov = _collect_auth_signal()
    sudoers_text, sudo_cov = _collect_sudoers()
    world_writable, fs_cov = _collect_world_writable()

    coverage = proc_cov + net_cov + auth_cov + sudo_cov + fs_cov

    return Collection(processes=processes, listeners = listeners, auth_signal=auth_signal, sudoers_text=sudoers_text,world_writable=world_writable, coverage=coverage)



            