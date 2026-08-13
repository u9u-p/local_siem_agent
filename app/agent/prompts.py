# app/agent/prompts.py
from app.agent.schemas import RecommendedAction
from app.schemas import Alert

_COMMAND_CONTEXT_CHAR_CAP = 500


def _truncate(text) -> str:
    if not text:
        return "none"
    return text if len(text) <= _COMMAND_CONTEXT_CHAR_CAP else text[:_COMMAND_CONTEXT_CHAR_CAP] + "...(truncated)"


def _command_context_block(command_context) -> str:
    if command_context is None:
        return ""
    decoded_summary = "\n".join(
        f"  - [{s.encoding}] {_truncate(s.decoded)}" for s in command_context.decoded_segments
    ) or "  none"
    return (
        f"Command line: {_truncate(command_context.command_line)}\n"
        f"Parent command line: {_truncate(command_context.parent_command_line)}\n"
        f"Decoded command segments:\n{decoded_summary}\n\n"
    )


def build_extract_indicators_prompt(alert: Alert, extra_texts: list[str] | None = None) -> str:
    extra_block = ""
    if extra_texts:
        extra_block = "Additional decoded command-line text:\n" + "\n".join(f"- {t}" for t in extra_texts) + "\n\n"
    return (
        "You are extracting security indicators (IP addresses, file hashes, domains, URLs) "
        "from a SIEM alert's raw log text. Some indicators may be obfuscated or defanged "
        "(e.g. '185[.]220[.]101[.]1' instead of '185.220.101.1', 'hxxp://' instead of 'http://').\n\n"
        f"Raw log: {alert.full_log}\n"
        f"Additional decoded fields: {alert.data}\n\n"
        f"{extra_block}"
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
        "(same_src_ip_24h, same_rule_id_host, same_dst_host, same_command_line_env_wide, or none_needed) "
        "if further investigation "
        "of one of the canonical searches would help confirm the pattern."
    )


def build_risk_assessment_prompt(alert, pattern_type, evidence_count, enrichment_results, command_context=None) -> str:
    enrichment_summary = "\n".join(
        f"- {e.indicator_type.value} {e.indicator_value}: {e.verdict.value} (provider {e.provider_id})"
        for e in enrichment_results
    ) or "none"
    mitre_summary = (
        ", ".join(f"{m.technique_id} ({m.technique_name})" for m in alert.mitre) if alert.mitre else "none mapped"
    )
    return (
        "You are assessing the risk of a security alert for a human analyst to review.\n\n"
        f"Rule: {alert.rule_id} - {alert.rule_description} (level {alert.rule_level}, "
        f"groups: {', '.join(alert.rule_groups)}).\n"
        f"Known MITRE ATT&CK mapping: {mitre_summary}.\n"
        f"Correlation findings: pattern_type={pattern_type.value}, evidence_count={evidence_count}.\n"
        f"Enrichment findings:\n{enrichment_summary}\n\n"
        f"{_command_context_block(command_context)}"
        "Assess the severity (low/medium/high/critical), your confidence in this assessment "
        "(low/medium/high), and a one-to-two-sentence rationale."
    )


def build_open_value_search_prompt(alert, canonical_results) -> str:
    findings_summary = "\n".join(
        f"- {template.value}: {result.total_count} matching alert(s)"
        for template, result in canonical_results.items()
    )
    return (
        "The closed-menu correlation searches below did not find or explain a clear pattern for "
        "this security alert. Propose ONE additional free-text search value (not a field name) "
        "that might surface related evidence in the alert log text.\n\n"
        f"Alert: rule {alert.rule_id} ({alert.rule_description}), level {alert.rule_level}.\n\n"
        f"Canonical search results:\n{findings_summary}\n\n"
        "Respond with a single search_value string."
    )


def _findings_block(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context=None) -> str:
    enrichment_summary = "\n".join(
        f"- {e.indicator_type.value} {e.indicator_value}: {e.verdict.value} (provider {e.provider_id})"
        for e in enrichment_results
    ) or "none"
    return (
        f"Rule: {alert.rule_id} - {alert.rule_description} (level {alert.rule_level}, "
        f"groups: {', '.join(alert.rule_groups)}).\n"
        f"Correlation findings: pattern_type={pattern_type.value}, evidence_count={evidence_count}.\n"
        f"Enrichment findings:\n{enrichment_summary}\n"
        f"Risk assessment: severity={risk_assessment.severity.value}, confidence={risk_assessment.confidence.value}, "
        f"rationale: {risk_assessment.rationale}\n"
        f"{_command_context_block(command_context)}"
    )


def build_draft_canonical_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context=None) -> str:
    action_menu = "\n".join(f"- {a.value}" for a in RecommendedAction)
    return (
        "You are drafting the canonical, vetted section of a security investigation report for a human analyst.\n\n"
        f"{_findings_block(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context)}\n"
        "Write a plain-language alert_summary (1-2 sentences), an expanded rationale (2-4 sentences) explaining "
        "the risk assessment above in more detail, and select every recommended_action below that applies to "
        "this alert — you MUST only pick from this exact list:\n"
        f"{action_menu}"
    )


def build_draft_experimental_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context=None) -> str:
    return (
        "You are drafting an EXPERIMENTAL, not-yet-vetted section of a security investigation report. "
        "This output will be clearly labeled experimental and will not be treated as trusted guidance.\n\n"
        f"{_findings_block(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context)}\n"
        "Freely propose any additional recommended actions in your own words (no fixed list this time), then "
        "classify whether this alert looks like a true_positive, false_positive, or uncertain, with a "
        "one-sentence rationale for that triage call."
    )


def build_self_check_prompt(draft, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context=None) -> str:
    claims = [draft.alert_summary, draft.rationale, *[a.value for a in draft.recommended_actions]]
    claims_block = "\n".join(f"{i + 1}. {claim}" for i, claim in enumerate(claims))
    enrichment_summary = "\n".join(
        f"- {e.indicator_type.value} {e.indicator_value}: {e.verdict.value} (provider {e.provider_id})"
        for e in enrichment_results
    ) or "none"
    return (
        "You are auditing a draft security report against the structured findings that produced it. "
        "For EACH numbered claim below, decide whether the structured findings support it. If not, and you "
        "can propose a better-supported replacement, provide a correction; otherwise leave correction empty.\n\n"
        f"Correlation findings: pattern_type={pattern_type.value}, evidence_count={evidence_count}.\n"
        f"Enrichment findings:\n{enrichment_summary}\n"
        f"Risk assessment: severity={risk_assessment.severity.value}, confidence={risk_assessment.confidence.value}.\n\n"
        f"{_command_context_block(command_context)}"
        f"Claims to audit, in order:\n{claims_block}\n\n"
        "Return exactly one audit per claim, in the same order."
    )
