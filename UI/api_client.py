"""
Único archivo del cliente que sabe que existe una red.
main_window.py NUNCA debe importar `requests` directamente.
"""

from typing import Optional
import requests
from models import Evento, Estadisticas

API_BASE = "http://localhost:8080"


class ApiClient:
    def __init__(self, base_url: str = API_BASE):
        self.base_url = base_url

    def _post(self, path: str) -> dict:
        try:
            r = requests.post(f"{self.base_url}{path}", timeout=3)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def _get_json(self, path: str, params: dict | None = None):
        try:
            r = requests.get(f"{self.base_url}{path}", params=params, timeout=3)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException:
            return None

    def start(self) -> dict:
        return self._post("/start")

    def stop(self) -> dict:
        return self._post("/stop")

    def get_events(self) -> list[Evento]:
        data = self._get_json("/events")
        if not data:
            return []
        return [Evento.from_dict(e) for e in data]

    def get_alerts(self) -> list[Evento]:
        data = self._get_json("/alerts")
        if not data:
            return []
        return [Evento.from_dict(e) for e in data]

    def get_statistics(self) -> Estadisticas | None:
        data = self._get_json("/statistics")
        if not data:
            return None
        return Estadisticas.from_dict(data)

    def clear(self) -> dict:
        return self._post("/clear")

    def search(self, ip: Optional[str] = None, port: Optional[int] = None) -> list[Evento]:
        params = {}
        if ip:
            params["ip"] = ip
        if port:
            params["port"] = port
        data = self._get_json("/search", params=params)
        if not data:
            return []
        return [Evento.from_dict(e) for e in data]
