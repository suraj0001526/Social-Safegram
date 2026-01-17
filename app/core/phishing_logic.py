import requests
import base64

def assess_url(url: str, api_key: str):
    """
    Scans a URL using VirusTotal API.
    """
    if not api_key or "xxxx" in api_key:
        return {"risk_level": "ERROR", "risk_score": 0, "flags": "Invalid API Key in main.py"}

    # 1. Encode URL for VirusTotal
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            malicious = stats['malicious']
            suspicious = stats['suspicious']
            total_bad = malicious + suspicious
            
            if total_bad > 0:
                return {
                    "risk_level": "CRITICAL",
                    "risk_score": max(0, 100 - (total_bad * 10)),
                    "flags": f"⚠️ Flagged by {total_bad} security vendors."
                }
            else:
                return {
                    "risk_level": "SAFE",
                    "risk_score": 100,
                    "flags": "✅ Clean by 70+ vendors."
                }
                
        elif response.status_code == 404:
            return {"risk_level": "UNKNOWN", "risk_score": 50, "flags": "❓ URL not in database."}
        else:
            return {"risk_level": "ERROR", "risk_score": 0, "flags": f"API Error: {response.status_code}"}

    except Exception as e:
        return {"risk_level": "ERROR", "risk_score": 0, "flags": str(e)}