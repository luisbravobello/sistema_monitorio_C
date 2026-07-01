"""
api_client.py
-------------
Esta es la UNICA pieza de la UI que sabe que existe una red.
main_window.py nunca importa `requests` directamente: solo llama a
estas funciones y recibe listas/diccionarios ya parseados desde JSON.

El backend debe estar corriendo en http://localhost:8080
(ver Backend/src/main.c -> arranca api_server_start(8080)).

Patrón que se repite en todo el archivo:
1. requests.get/post(...)   -> hace la petición HTTP.
2. timeout=TIMEOUT          -> evita que la UI se cuelgue si el backend no responde.
3. r.raise_for_status()     -> si el backend devuelve un error (404, 500),
                                lanza una excepción aquí mismo, así un solo
                                try/except en main_window.py cubre todos los casos.
4. r.json()                 -> convierte el texto JSON crudo en listas/dicts de Python.
"""

import requests

BASE_URL = "http://localhost:8080"
TIMEOUT = 3  # segundos máximos de espera por respuesta del backend


def iniciar_captura(device: str | None = None) -> dict:
    """
    POST /start  (opcionalmente ?device=eth0)

    Le pide al backend que arranque la captura de paquetes.
    Relacionado con: api_server.c -> handle_start()
        - Si ya había una captura corriendo, el backend NO lanza error:
          responde {"status": "ya estaba corriendo"} (200 OK).
        - Si se manda 'device', el backend lo guarda en g_capture_device
          y lo usa al iniciar el hilo de captura (capture_thread_main).
        - Si no se manda nada, el backend usa "any" por defecto.

    Retorna: dict, ej: {"status": "capturando"}
    """
    url = f"{BASE_URL}/start"
    if device:
        url += f"?device={device}"
    r = requests.post(url, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def detener_captura() -> dict:
    """
    POST /stop

    Le pide al backend que detenga la captura de paquetes en curso.
    Relacionado con: api_server.c -> handle_stop()
        - Si había una captura activa, el backend llama internamente a
          data_reader_stop_capture() y espera (pthread_join) a que el
          hilo de captura termine antes de responder.
        - Si no había ninguna captura corriendo, igual responde 200 OK.

    Retorna: dict, ej: {"status": "detenido"}
    """
    r = requests.post(f"{BASE_URL}/stop", timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def obtener_eventos() -> list:
    """
    GET /events

    Trae todos los eventos detectados, sin filtrar.
    Relacionado con: api_server.c -> handle_events() -> viewmodel_events_to_json()

    Retorna: lista de dicts, ej:
        [{"ip": "10.0.0.2", "puerto": 22, "tipo": "SSH_BRUTE",
          "severidad": 4, "timestamp": 1782846959}, ...]
    """
    r = requests.get(f"{BASE_URL}/events", timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def obtener_alertas() -> list:
    """
    GET /alerts

    Trae solo las amenazas confirmadas (confirmed == 1 del lado del
    backend), ya ordenadas de mayor a menor severidad.
    Relacionado con: api_server.c -> handle_alerts() -> viewmodel_alerts_to_json()
        - viewmodel.c hace una COPIA del arreglo, la ordena con
          sort_by_severity() y filtra solo los confirmados, así que
          la UI recibe la lista ya lista para mostrar tal cual.

    Retorna: mismo formato que obtener_eventos(), pero ya filtrada.
    """
    r = requests.get(f"{BASE_URL}/alerts", timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def obtener_estadisticas() -> dict:
    """
    GET /statistics

    Trae el resumen general del tráfico detectado.
    Relacionado con: api_server.c -> handle_statistics() -> viewmodel_statistics_to_json()

    Retorna: dict, ej:
        {"total_paquetes": 7,
         "amenazas_por_tipo": {"SSH_BRUTE": 7},
         "amenazas_por_severidad": {"4": 7}}
    """
    r = requests.get(f"{BASE_URL}/statistics", timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def buscar(ip: str | None = None, port: int | None = None) -> list:
    """
    GET /search?ip=&port=

    Filtra eventos por IP de origen y/o puerto de destino.
    Relacionado con: api_server.c -> handle_search()
        - El backend filtra MANUALMENTE sobre su arreglo interno
          (no usa search_linear_by_ip aquí, esa función existe en
          search.c pero el endpoint /search hace su propio filtrado).
        - Importante: esta función SIEMPRE le pega al backend, nunca
          filtra localmente sobre datos que la UI ya tenga cargados,
          para que el resultado sea exacto.

    Parámetros:
        ip   -- IP de origen a buscar (opcional)
        port -- puerto de destino a buscar (opcional)
        Se pueden combinar o dejar uno solo.

    Retorna: mismo formato que obtener_eventos(), ya filtrado.
    """
    params = {}
    if ip:
        params["ip"] = ip
    if port is not None:
        params["port"] = port
    r = requests.get(f"{BASE_URL}/search", params=params, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def limpiar_eventos() -> dict:
    """
    POST /clear

    Borra todos los eventos guardados en el backend.
    Relacionado con: api_server.c -> route_request() -> api_server_clear_events()
        - Esto resetea g_event_count a 0 del lado del backend (con el
          mutex bloqueado, así que es seguro aunque haya una captura
          corriendo al mismo tiempo).
        - No borra nada en disco: todo el estado del backend vive en
          memoria, así que esto es solo "vaciar la sesión actual".

    Retorna: dict, ej: {"status": "limpiado"}
    """
    r = requests.post(f"{BASE_URL}/clear", timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()