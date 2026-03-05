from urllib.parse import urlparse


INTERNAL_DOMAINS = {"company.com", "company.internal"}


def _extract_domain_from_email(sender: str) -> str | None:
    if "@" not in sender:
        return None
    return sender.split("@", 1)[1].lower().strip()


def _extract_domain_from_url(url: str) -> str | None:
    try:
        return urlparse(url).netloc.lower().strip()
    except Exception:
        return None


def collect_evidence(alert: dict) -> dict:
    sender = alert.get("sender", "") or ""
    url = alert.get("url")
    attachment = alert.get("attachment")

    sender_domain = _extract_domain_from_email(sender)
    url_domain = _extract_domain_from_url(url) if url else None

    is_internal_sender = (sender_domain in INTERNAL_DOMAINS) if sender_domain else False

    evidence = {
        "sender_domain": sender_domain,
        "url_domain": url_domain,
        "is_internal_sender": is_internal_sender,
        "external_sender": not is_internal_sender,
        "has_url": url is not None,
        "has_attachment": attachment is not None,
        "attachment_type": None,
    }

    if attachment:
        evidence["attachment_type"] = (attachment.get("file_type") or "").lower() or None

    return evidence