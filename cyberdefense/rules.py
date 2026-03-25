from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .collect import Collection, ListeningPort
from .model import Finding

@dataclass(frozen=True)
class RuleResult:
    findings: list[Finding]


RISKY_PORTS = {21, 22, 23, 25, 110, 139, 445, 1433, 3306, 3389, 5000, 5432, 5900, 6379, 7000, 27017}


def _is_public_listener(listener: ListeningPort) -> bool:
    addr = listener.local_addr
    return addr in {"0.0.0.0", "::", "*", ""} or addr.startswith("::")

def rule_public_listeners(collection: Collection) -> list[Finding]:
    findings: list[Finding] = []
    public = [l for l in collection.listeners if _is_public_listener(l)]
    for listener in public:
        if listener.port in RISKY_PORTS:
            findings.append(Finding(finding_id=f"PUBLIC_PORT_{listener.port}", severity="high", title=f"Public listener on risky port {listener.port}", detail="A service on a public interface is listening for a commonly targeted port.", evidence={"local_addr": listener.local_addr, "port": listener.port,"proto": listener.proto}, remediation= "Restrict the service to localhost, add firewall rules, or disable it if it isn't in use", tags= ["network", "exposure"]))

    if len(public) >= 1:
        findings.append(Finding(finding_id="MANY_PUBLIC_LISTENERS", severity="medium",title="Many public listening ports", detail="Many services listening on public interfaces, increasing attack surface.", evidence={"count": len(public)}, remediation="Disable unused services and restrict bind addresses to localhost where possible", tags=["network", "exposure"]))

    return findings

def rule_world_writable(collection: Collection) -> list[Finding]:
    if not collection.world_writable:
        return []
    return [Finding(finding_id = "WORLD_WRITABLE_SYSTEM_PATHS",
                    severity="high",
                    title="World-writable system paths",
                    detail="Files in system directories are writable by all users",
                    evidence={"paths": collection.world_writable[:20], "total": len(collection.world_writable)},
                    remediation="Remove world-writable permissions and review ownership for these paths",
                    tags=["filesystem", "permissions"])]

def rule_nopasswd_sudo(collection: Collection) -> list[Finding]:
    sudoers = collection.sudoers_text
    if not sudoers:
        return []
    if re.search(r"NOPASSWD", sudoers):
        return[Finding(finding_id="NOPASSWD_SUDO",
                       severity="medium",
                       title="Passwordless sudo detected",
                       detail="NOPASSWD entries allow sudo without prompting for a password",
                       evidence={"source": "/etc/sudoers"},
                       remediation="Remove NOPASSWD entries or restrict them to specific commands.",
                       tags=["privilege", "policy"])]
    return []


def rule_failed_logins(collection: Collection) -> list[Finding]:
    auth = collection.auth_signal
    if not auth:
        return []
    if auth.failed_logins >= 10:
        return [Finding(finding_id="FAILED_LOGINS",
                        severity="medium",
                        title="Multiple failed login attempts",
                        detail="Recent authentication logs show repeated failed logins.",
                        evidence={"count": auth.failed_logins, "source": auth.raw_source},
                        remediation="Review account security, enable MFA, and consider fail2ban or equivalent controls.",
                        tags=["auth", "bruteforce"])]

    return []


def evaluate_rules(collection: Collection) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(rule_public_listeners(collection))
    findings.extend(rule_world_writable(collection))
    findings.extend(rule_nopasswd_sudo(collection))
    findings.extend(rule_failed_logins(collection))

    return findings