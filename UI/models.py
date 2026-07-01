"""
Clases ligeras que reflejan el JSON que entrega la API REST en C.
Este archivo es la única fuente de verdad sobre la forma de los datos
en el lado de Python — debe mantenerse sincronizado con
docs/API_CONTRACT.md cada vez que cambie algo del lado de C.
"""

from dataclasses import dataclass


@dataclass
class Evento:
    ip: str
    puerto: int
    tipo: str
    severidad: int
    timestamp: int

    @classmethod
    def from_dict(cls, data: dict) -> "Evento":
        return cls(
            ip=data["ip"],
            puerto=data["puerto"],
            tipo=data["tipo"],
            severidad=data["severidad"],
            timestamp=data["timestamp"],
        )


@dataclass
class Estadisticas:
    total_paquetes: int
    amenazas_por_tipo: dict
    amenazas_por_severidad: dict

    @classmethod
    def from_dict(cls, data: dict) -> "Estadisticas":
        return cls(
            total_paquetes=data.get("total_paquetes", 0),
            amenazas_por_tipo=data.get("amenazas_por_tipo", {}),
            amenazas_por_severidad=data.get("amenazas_por_severidad", {}),
        )