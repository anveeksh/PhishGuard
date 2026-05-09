import whois
from datetime import datetime, timezone

def get_domain_age(domain: str) -> dict:
    """
    Look up domain registration age via WHOIS.
    Returns age in days and risk assessment.
    """
    try:
        data = whois.whois(domain)
        creation_date = data.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {
                "available": False,
                "age_days": None,
                "verdict": "unknown",
                "reason": "Domain age could not be determined.",
                "risk_score": 6
            }

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation_date).days

        if age_days < 7:
            verdict = "very_new"
            reason  = f"Domain was registered {age_days} day(s) ago — extremely suspicious."
            risk    = 35
        elif age_days < 30:
            verdict = "new"
            reason  = f"Domain was registered {age_days} days ago — recently created domains are high risk."
            risk    = 22
        elif age_days < 90:
            verdict = "recent"
            reason  = f"Domain is only {age_days} days old — less than 3 months."
            risk    = 10
        else:
            verdict = "established"
            reason  = None
            risk    = 0

        return {
            "available":   True,
            "age_days":    age_days,
            "created":     creation_date.strftime("%Y-%m-%d"),
            "registrar":   str(data.registrar or "Unknown"),
            "verdict":     verdict,
            "reason":      reason,
            "risk_score":  risk
        }

    except Exception as e:
        return {
            "available": False,
            "age_days":  None,
            "verdict":   "unknown",
            "reason":    "WHOIS lookup failed — domain age unverified.",
            "risk_score": 5
        }
