# Sistema de Monitoreo de Amenazas de Red

Sistema de monitoreo de tráfico de red en tiempo real, capaz de detectar amenazas como escaneos de puertos y ataques de fuerza bruta por SSH. Backend en **C** (servidor HTTP + motor de detección) y UI en **Python** que consume su API REST.

## Autores

| Rol | Nombre |
|---|---|
| Backend | Luis Alejandro Bravo Bello |
| UI | Ronald Alberto Reyes Sánchez |

## Características principales

- Captura en vivo (libpcap) o lectura desde archivo de log.
- Detección de `PORT_SCAN` y `SSH_BRUTE` por ventana de tiempo (10 s).
- Ordenamiento de eventos por timestamp y por severidad (inserción).
- Búsqueda de eventos por IP (lineal) y por timestamp (binaria).
- API REST en `localhost:8080` consumida por la UI en Python.


## Estructura del proyecto

```
sistema_monitorio_C/
├── UI/
│   ├── main.py              Punto de entrada de la interfaz
│   ├── main_window.py       Ventana principal (PyQt / Tkinter)
│   ├── api_client.py        Cliente HTTP hacia el backend
│   ├── models.py            Modelos de datos en Python (espejo de models.h)
│   └── requirements.txt     Dependencias Python
│
└── Backend/
    ├── include/             Headers (.h)
    │   ├── models.h         Estructuras NetworkPacket y ThreatEvent
    │   ├── data_reader.h    Lectura de logs y captura en vivo (pcap)
    │   ├── detector.h       Motor de detección de amenazas
    │   ├── search.h         Búsqueda lineal y binaria sobre eventos
    │   ├── sort.h           Ordenamiento por timestamp y severidad
    │   ├── viewmodel.h      Serialización de eventos a JSON
    │   └── api_server.h     Servidor HTTP REST
    └── src/                 Implementaciones (.c)
        ├── main.c           Punto de entrada, arranca el servidor en :8080
        ├── api_server.c     Servidor HTTP con sockets (POSIX / Winsock)
        ├── data_reader.c    Lectura de logs y captura pcap (con simulador interno)
        ├── detector.c       Detección por ventana de tiempo (PORT_SCAN, SSH_BRUTE)
        ├── search.c         Búsqueda por IP (lineal) y timestamp (binaria)
        ├── sort.c           Quicksort/mergesort por timestamp y severidad
        └── viewmodel.c      Conversión de ThreatEvent[] a JSON
```

---

## Arquitectura

```
┌─────────────────────┐       HTTP REST        ┌────────────────────────┐
│      UI Python      │ ◄───────────────────► │     Backend C          │
│  (main_window.py)   │    localhost:8080       │   (api_server.c)       │
└─────────────────────┘                        └──────────┬─────────────┘
                                                          │
                               ┌──────────────────────────┼──────────────────────┐
                               ▼                          ▼                      ▼
                        data_reader.c              detector.c             viewmodel.c
                     (pcap / log file)        (PORT_SCAN, SSH_BRUTE)   (JSON responses)
```

El backend corre un servidor HTTP minimalista sobre sockets puros (sin librerías externas). La captura de red usa **libpcap** si está disponible; si no, cae en un simulador interno para pruebas.

---

## Modelos de datos

### `NetworkPacket`
Representa un paquete de red interceptado (en vivo o desde log).

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `src_ip` | `char[46]` | IP de origen (IPv4 o IPv6) |
| `dst_ip` | `char[46]` | IP de destino |
| `src_port` | `int` | Puerto de origen |
| `dst_port` | `int` | Puerto de destino |
| `protocol` | `char[8]` | TCP, UDP o ICMP |
| `size` | `int` | Tamaño del paquete en bytes |
| `timestamp` | `time_t` | Marca de tiempo Unix |

### `ThreatEvent`
Alerta generada cuando el detector identifica una anomalía.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `packet` | `NetworkPacket` | Paquete que disparó la alerta |
| `threat_type` | `char[32]` | `PORT_SCAN` o `SSH_BRUTE` |
| `severity` | `int` | Nivel del 1 (Bajo) al 5 (Crítico) |
| `confirmed` | `int` | `0` = Sospecha, `1` = Confirmado |

---

## API REST

El servidor escucha en `http://localhost:8080`.

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/start?device=X` | Inicia la captura de paquetes en la interfaz `X` |
| `POST` | `/stop` | Detiene la captura |
| `GET` | `/events` | Retorna todos los eventos detectados (JSON) |
| `GET` | `/alerts` | Retorna solo las amenazas confirmadas, ordenadas por severidad (JSON) |
| `GET` | `/statistics` | Resumen general: cantidad de paquetes, tipos de ataque, niveles de severidad (JSON) |
| `GET` | `/search?ip=&port=` | Filtra eventos por IP de origen o puerto |

---

## Motor de detección

El detector (`detector.c`) usa una **ventana deslizante de 10 segundos** para identificar patrones de ataque provenientes de una misma IP:

| Amenaza | Condición | Severidad | Estado |
|---------|-----------|-----------|--------|
| `PORT_SCAN` | ≥ 5 puertos distintos en 10 s | 3 | Sospecha |
| `SSH_BRUTE` | ≥ 4 conexiones al puerto 22 en 10 s | 4 | Confirmado |

El historial interno mantiene las últimas **256 entradas** en un buffer circular.

---

## Compilación y ejecución

**Windows (MinGW):**
```bash
gcc -std=c11 -Iinclude src/*.c -o monitor.exe -lws2_32
./monitor.exe
```

**Linux/macOS:**
```bash
gcc -std=c11 -Iinclude src/*.c -o monitor -lpthread
./monitor
```

**UI:**
```bash
cd UI
pip install -r requirements.txt
python main.py
```

> Compilar con `-DHAVE_PCAP` (y enlazar `-lwpcap`/`-lpcap`) habilita la captura real de tráfico; si no, el sistema usa un simulador interno.

## Documentación completa

Para la especificación de requisitos, arquitectura, diseño y decisiones técnicas, ver [`docs/ERS.md`](docs/ERS.md).
