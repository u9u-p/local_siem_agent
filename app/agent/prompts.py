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
