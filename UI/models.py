"""
models.py
---------
Clases que representan el JSON que manda el backend en C.

IMPORTANTE (verificado directamente en el código real del Backend):
    - Backend/include/models.h SI tiene un campo `confirmed` en ThreatEvent,
      pero Backend/src/viewmodel.c NUNCA lo agrega al JSON de salida.
    - Es decir: el JSON real de /events, /alerts y /search siempre trae
      solo estos 5 campos: ip, puerto, tipo, severidad, timestamp.
    - Por eso NO creamos un campo `confirmed` aca: mostrar ese dato
      seria inventarlo, ya que nunca llega desde el backend.
    - Si en el futuro Luis agrega `confirmed` al JSON, solo hay que
      agregar el campo aca (ver nota al final del archivo).
"""

from dataclasses import dataclass
from datetime import datetime

# Nombre legible de cada nivel de severidad (1 = bajo .. 5 = critico)
NIVELES_SEVERIDAD = {
    1: "Bajo",
    2: "Medio-Bajo",
    3: "Medio",
    4: "Alto",
    5: "Critico",
}


@dataclass
class Evento:
    ip: str
    puerto: int
    tipo: str        # "PORT_SCAN" o "SSH_BRUTE" (u otro que agregue el backend)
    severidad: int    # 1 al 5 (pero ver nivel() abajo: se blinda ante otros valores)
    timestamp: int    # unix timestamp (segundos desde 1970)

    @property
    def fecha(self) -> str:
        """
        Timestamp en formato legible: '2023-11-14 22:13:20'.
        Blindado: si el timestamp viene corrupto o negativo (bug del
        backend, reloj mal puesto, etc.), no truena toda la tabla —
        muestra un texto de aviso en esa fila y ya.
        """
        try:
            return datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError, OverflowError):
            return "Fecha invalida"

    @property
    def nivel(self) -> str:
        """Nombre del nivel de severidad. Si el backend manda un
        numero fuera de 1-5, no truena: cae en 'Desconocido'."""
        return NIVELES_SEVERIDAD.get(self.severidad, "Desconocido")

    @classmethod
    def desde_dict(cls, d: dict) -> "Evento":
        """
        Construye un Evento a partir del dict que devuelve requests.json().
        Usa .get(...) con valores por defecto en vez de d["ip"] directo:
        si el backend un dia manda un evento con un campo faltante o
        nulo (por un bug de su lado), esto no tumba toda la UI — se
        completa con un valor neutro y se ve una fila "rara" en vez
        de una pantalla de error completa.
        """
        return cls(
            ip=str(d.get("ip", "desconocida")),
            puerto=int(d.get("puerto", 0) or 0),
            tipo=str(d.get("tipo", "DESCONOCIDO")),
            severidad=int(d.get("severidad", 0) or 0),
            timestamp=int(d.get("timestamp", 0) or 0),
        )


@dataclass
class Estadisticas:
    total_paquetes: int
    amenazas_por_tipo: dict       # ej: {"SSH_BRUTE": 10, "PORT_SCAN": 5}
    amenazas_por_severidad: dict  # ej: {"3": 5, "4": 10}  (claves como texto, asi las manda el backend)

    @classmethod
    def desde_dict(cls, d: dict) -> "Estadisticas":
        return cls(
            total_paquetes=int(d.get("total_paquetes", 0) or 0),
            amenazas_por_tipo=d.get("amenazas_por_tipo") or {},
            amenazas_por_severidad=d.get("amenazas_por_severidad") or {},
        )


# NOTA PARA CUANDO LUIS ARREGLE EL BACKEND:
# Si en algun momento /events o /alerts empiezan a mandar "confirmed"
# en el JSON, agregar aca:
#     confirmed: bool
# y en desde_dict():
#     confirmed=bool(d.get("confirmed", 0)),
# Mientras tanto, la pestana de Alertas de la UI no necesita ese campo
# porque el propio backend ya filtra /alerts para devolver solo
# eventos confirmados.