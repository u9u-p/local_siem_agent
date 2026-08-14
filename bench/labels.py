"""Ground truth for the local-model-selection benchmark.

Labels are derived from alert *content*, never from `alert_id`. `alert_id` is a
uuid5 of the Wazuh source id (`<epoch>.<counter>`), which is minted fresh every
time the stack is re-seeded — an id-keyed labels file would rot silently on the
next `docker compose down -v`. Rule id plus one discriminator survives re-ingestion.

See docs/superpowers/specs/2026-08-14-local-model-selection-benchmark-design.md §2.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Role(str, Enum):
    BENIGN = "benign"
    NEEDLE = "needle"
    FP_CONTROL = "fp_control"


@dataclass(frozen=True)
class Label:
    cluster: str
    role: Role
    #: Severities that count as correct. Everything the pipeline can emit is
    #: low/medium/high/critical; benign is allowed medium because a held-for-review
    #: message or an unrecognised logon genuinely warrants a second look — what it
    #: must not do is escalate.
    expect_severity: frozenset[str]
    expect_triage: str

    @property
    def escalated_is_wrong(self) -> bool:
        return self.role is not Role.NEEDLE


_BENIGN = dict(expect_severity=frozenset({"low", "medium"}), expect_triage="false_positive")
_MALICIOUS = dict(expect_severity=frozenset({"high", "critical"}), expect_triage="true_positive")


def expected_for(cluster: str, role: Role) -> Label:
    """Rebuild a label from a recorded (cluster, role) pair.

    The scorer re-derives expectations here rather than trusting a copy written into
    the results file, so a labelling change can never disagree with an old run's
    stored opinion of what "correct" meant.
    """
    return Label(cluster, role, **(_MALICIOUS if role is Role.NEEDLE else _BENIGN))


def label_for(rule_id: str, rule_description: str, source_ip: str | None) -> Label | None:
    """Return the graded label for an alert, or None if it is not in the graded set.

    Each cluster is a flood of near-identical alerts on one rule at one level, so the
    discriminator is whatever the rule description or source address carries — which is
    also the only channel the Risk step ever sees.
    """
    desc = rule_description or ""

    if rule_id == "100075":  # encoded PowerShell, 40 benign : 1 needle
        needle = "wscript.exe" in desc.lower()
        return Label("powershell", Role.NEEDLE if needle else Role.BENIGN,
                     **(_MALICIOUS if needle else _BENIGN))

    if rule_id == "106001":  # held-for-review mail, 35 benign : 1 phishing chain
        needle = "secure-invoice-updates.com" in desc.lower()
        return Label("email", Role.NEEDLE if needle else Role.BENIGN,
                     **(_MALICIOUS if needle else _BENIGN))

    if rule_id == "100080":  # SSH success, 30 benign : 1 needle
        needle = source_ip == "45.146.164.110"
        return Label("ssh", Role.NEEDLE if needle else Role.BENIGN,
                     **(_MALICIOUS if needle else _BENIGN))

    if rule_id == "100061":  # Windows logon; mrahman's VPN egress is the FP control
        if source_ip == "100.72.44.19":
            # Known to fail while Correlate sees only counts (spec §2, §6.2). Graded
            # anyway: if a model resists, that is the single most interesting result
            # in the sweep.
            return Label("winlogon", Role.FP_CONTROL, **_BENIGN)
        return Label("winlogon", Role.BENIGN, **_BENIGN)

    if rule_id in {"100073", "100074"}:  # Scenario C true-positive chain, baseline
        return Label("tp_chain", Role.NEEDLE, **_MALICIOUS)

    return None


def demo() -> None:
    phish = label_for("106001", "Message <x@secure-invoice-updates.com> held for review.", "185.220.101.47")
    assert phish is not None and phish.role is Role.NEEDLE and phish.expect_triage == "true_positive"

    benign_mail = label_for("106001", "Message <x@mailer.acmecloud.io> held for review.", "149.72.14.88")
    assert benign_mail is not None and benign_mail.role is Role.BENIGN
    assert benign_mail.escalated_is_wrong

    # The discriminator is the parent image, not the encoded payload.
    assert label_for("100075", r"...encoded command by C:\Windows\System32\wscript.exe.", None).role is Role.NEEDLE
    assert label_for("100075", r"...encoded command by C:\Program Files\nodejs\node.exe.", None).role is Role.BENIGN

    # SSH and Windows logon discriminate on address: the descriptions are otherwise identical.
    assert label_for("100080", "SSH: successful logon for user jsmith from 45.146.164.110.", "45.146.164.110").role is Role.NEEDLE
    assert label_for("100080", "SSH: successful logon for user ltan from 203.0.113.74.", "203.0.113.74").role is Role.BENIGN
    assert label_for("100061", "Windows: successful logon for user mrahman.", "100.72.44.19").role is Role.FP_CONTROL
    assert label_for("100061", "Windows: successful logon for user raj.kumar.", "10.20.4.73").role is Role.BENIGN

    # Ungraded alerts must be skipped, not silently scored as benign.
    assert label_for("5501", "PAM: Login session opened.", None) is None
    assert label_for("100051", "ocserv: User mrahman connected to VPN.", "203.0.113.30") is None

    print("labels: ok")


if __name__ == "__main__":
    demo()
