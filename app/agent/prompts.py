# app/agent/prompts.py
from app.schemas import Alert


def build_extract_indicators_prompt(alert: Alert) -> str:
    return (
        "You are extracting security indicators (IP addresses, file hashes, domains, URLs) "
        "from a SIEM alert's raw log text. Some indicators may be obfuscated or defanged "
        "(e.g. '185[.]220[.]101[.]1' instead of '185.220.101.1', 'hxxp://' instead of 'http://').\n\n"
        f"Raw log: {alert.full_log}\n"
        f"Additional decoded fields: {alert.data}\n\n"
        "List every candidate indicator you find, with its type (ip, file_hash, domain, or url) "
        "and its value in normal (de-obfuscated) form."
    )


def build_correlation_decision_prompt(alert, canonical_results, evidence_count) -> str:
    findings_summary = "\n".join(
        f"- {template.value}: {result.total_count} matching alert(s)"
        for template, result in canonical_results.items()
    )
    return (
        "You are analyzing correlation search results for a security alert.\n\n"
        f"Alert: rule {alert.rule_id} ({alert.rule_description}), level {alert.rule_level}.\n\n"
        f"Canonical search results:\n{findings_summary}\n\n"
        f"Total evidence count: {evidence_count}\n\n"
        "Classify the pattern_type (brute_force, scanning, lateral_movement, none, or other), "
        "and pick at most one follow_up_query from the closed menu "
        "(same_src_ip_24h, same_rule_id_host, same_dst_host, or none_needed) if further investigation "
        "of one of the canonical searches would help confirm the pattern."
    )
