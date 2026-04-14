import httpx
import asyncio
from backend.config import VT_API_KEY
from backend.utils.logger import log

VT_API_URL = "https://www.virustotal.com/api/v3"

class VirusTotalClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or VT_API_KEY
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}

    async def _request(self, method: str, endpoint: str, **kwargs):
        if not self.api_key:
            log.warning("VT_API_KEY not set. VirusTotal lookup is disabled.")
            return {"error": "Missing VT_API_KEY"}

        async with httpx.AsyncClient() as client:
            try:
                response = await client.request(
                    method, 
                    f"{VT_API_URL}{endpoint}", 
                    headers=self.headers, 
                    timeout=5.0,
                    **kwargs
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as exc:
                log.error(f"VirusTotal API Error: {exc}")
                return {"error": str(exc)}

    async def scan_url(self, url: str) -> dict:
        """Scan a URL using VT API"""
        payload = {"url": url}
        # First submit the URL
        submit_res = await self._request("POST", "/urls", data=payload)
        if "error" in submit_res:
            return submit_res
            
        # Get Analysis ID
        analysis_id = submit_res.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "Failed to get analysis ID"}

        # For performance under 2s, we will return the analysis queued info.
        # In a real heavy system, we might poll, but that violates <2s constraint often.
        return {"result": "queued", "analysis_id": analysis_id, "message": "URL submitted successfully for analysis."}
        
    async def get_url_report(self, url_id: str) -> dict:
        """Get report for URL (ID must be base64 URL w/o padding)"""
        return await self._request("GET", f"/urls/{url_id}")

    async def get_file_report(self, file_hash: str) -> dict:
        """Get report for a given Hash (MD5, SHA-1, SHA-256)"""
        return await self._request("GET", f"/files/{file_hash}")
