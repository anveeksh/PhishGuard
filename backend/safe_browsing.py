import httpx

SAFE_BROWSING_API_KEY = "AIzaSyD9IKrHPsX0xapE-Vt9azx_6Zk9xrF4g9g"
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

async def check_safe_browsing(url: str) -> dict:
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(SAFE_BROWSING_URL, json=payload)
            data = response.json()
            if data.get("matches"):
                threat = data["matches"][0]
                return {"flagged": True, "threat_type": threat.get("threatType","UNKNOWN"), "source": "Google Safe Browsing"}
            return {"flagged": False, "threat_type": None, "source": "Google Safe Browsing"}
    except Exception as e:
        return {"flagged": False, "threat_type": None, "error": str(e)}
