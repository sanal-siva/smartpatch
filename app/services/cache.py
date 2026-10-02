import json
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

class CacheManager:
    def __init__(self, ttl_hours: int = 24):
        self.cache: Dict[str, tuple] = {}
        self.ttl = timedelta(hours=ttl_hours)

    def get_cache_key(self, vulnerabilities: list) -> str:
        cve_ids = sorted([v.get("cve_id", "") for v in vulnerabilities])
        key_str = "|".join(cve_ids)
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if key not in self.cache:
            return None

        data, timestamp = self.cache[key]
        if datetime.utcnow() - timestamp > self.ttl:
            del self.cache[key]
            return None

        return data

    def set(self, key: str, data: Dict[str, Any]) -> None:
        self.cache[key] = (data, datetime.utcnow())

    def clear(self) -> None:
        self.cache.clear()
