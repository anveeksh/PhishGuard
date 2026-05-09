import httpx

VIRUSTOTAL_API_KEY = "cea2c2b4cbeb96a7bb7054a24931c4c99425ebf29394f512f1511a7d5313ee1c"
VT_URL_REPORT     = "https://www.virustotal.com/api/v3/urls"

async def check_virustotal(url: str) -> dict:
    """Submit URL to VirusTotal and get detection results."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:

            # Step 1: Submit URL for analysis
            submit = await client.post(
                VT_URL_REPORT,
                headers=headers,
                data={"url": url}
            )
            submit_data = submit.json()
            analysis_id = submit_data.get("data", {}).get("id")

            if not analysis_id:
                return {"available": False, "error": "Could not submit URL"}

            # Step 2: Get analysis results
            report = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )
            report_data = report.json()
            stats = report_data.get("data", {}).get("attributes", {}).get("stats", {})

            malicious  = stats.get("malicious",  0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values()) if stats else 0
            clean      = stats.get("undetected", 0)

            flagged = malicious > 0 or suspicious > 1

            return {
                "available":  True,
                "flagged":    flagged,
                "malicious":  malicious,
                "suspicious": suspicious,
                "clean":      clean,
                "total":      total,
                "score":      round((malicious / total) * 100) if total > 0 else 0,
                "source":     "VirusTotal"
            }

    except Exception as e:
        return {"available": False, "flagged": False, "error": str(e), "source": "VirusTotal"}
