# Sistema de Monitoreo de Amenazas de Red

Sistema de monitoreo de tráfico de red en tiempo real, capaz de detectar amenazas como escaneos de puertos y ataques de fuerza bruta por SSH. Backend en **C** (servidor HTTP + motor de detección) y UI en **Python** que consume su API REST.

## Autores

| Rol | Nombre |
|---|---|
| Backend | Luis Alejandro Bravo Bello |
| UI | Ronald Alberto Reyes Sánchez |

## Características principales

- Captura en vivo (libpcap) o lectura desde archivo de log.
- Detección de `PORT_SCAN` y `SSH_BRUTE` por ventana de tiempo (15 s).
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
| `POST` | `/start?device=X` | Inicia la captura de paquetes en la interfaz `X` (síncrono: si falla, devuelve el error real) |
| `POST` | `/stop` | Detiene la captura |
| `GET` | `/events` | Retorna todos los eventos detectados, ordenados por timestamp ascendente (JSON) |
| `GET` | `/alerts` | Retorna solo las amenazas confirmadas, ordenadas por severidad (JSON) |
| `GET` | `/statistics` | Resumen general: cantidad de paquetes, tipos de ataque, niveles de severidad (JSON) |
| `GET` | `/search?ip=&port=&timestamp=` | Filtra eventos por IP de origen, puerto o timestamp exacto (búsqueda binaria) |
| `GET` | `/devices` | Lista las interfaces reales detectadas por Npcap/libpcap y el flag `real_capture` |
| `POST` | `/clear` | Limpia todos los eventos y alertas almacenados en memoria |
| `POST` | `/simulate?type=` | Genera una alerta de prueba (`ssh_brute` o `port_scan`) sin necesidad de tráfico real |

---

## Motor de detección

El detector (`detector.c`) usa una **ventana deslizante de 15 segundos** para identificar patrones de ataque provenientes de una misma IP:

| Amenaza | Condición | Severidad | Estado |
|---------|-----------|-----------|--------|
| `PORT_SCAN` | ≥ 4 puertos distintos en 15 s | 3 | Sospecha |
| `SSH_BRUTE` | ≥ 3 conexiones al puerto 22 en 15 s | 4 | Confirmado |

El historial interno mantiene las últimas **256 entradas** en un buffer circular. Los eventos confirmados se guardan en un arreglo de hasta **5000 posiciones** (`MAX_EVENTS`) y las alertas en uno de hasta **1000** (`MAX_ALERTS`).

---

## Compilación y ejecución

Por defecto (sin `-DHAVE_PCAP`) el backend usa un simulador interno de
tráfico. Para capturar tráfico REAL hay que compilar con `-DHAVE_PCAP`
enlazando Npcap (Windows) o libpcap (Linux/macOS). Los scripts
`build.bat` / `build.sh` ya hacen esto por vos.

### Windows (captura real con Npcap) — recomendado

1. Instala Npcap marcando "WinPcap API-compatible Mode": https://npcap.com/#download
2. Descarga el Npcap SDK (mismo link) y descomprimelo en `Backend/npcap-sdk/`
   (debe quedar `Backend/npcap-sdk/Include` y `Backend/npcap-sdk/Lib`).
3. Con MinGW (gcc) en el PATH:
   ```bash
   cd Backend
   build.bat
   ```
4. Ejecuta `monitor.exe` COMO ADMINISTRADOR (Npcap lo exige).

Compilación manual equivalente:
```bash
gcc -std=c11 -DHAVE_PCAP -Iinclude -Inpcap-sdk\Include src\*.c -o monitor.exe -Lnpcap-sdk\Lib\x64 -lwpcap -lPacket -lws2_32
```

### Windows sin captura real (solo simulador, para pruebas rápidas)
```bash
cd Backend
gcc -std=c11 -Iinclude src/*.c -o monitor.exe -lws2_32
./monitor.exe
```

### Linux/macOS (captura real con libpcap)
```bash
cd Backend
sudo apt-get install libpcap-dev   # una sola vez (Debian/Ubuntu)
./build.sh
sudo ./monitor      # o: sudo setcap cap_net_raw,cap_net_admin=eip ./monitor
```

# UI (Python) 
```bash
cd UI
pip install -r requirements.txt
python main.py
```

## Endpoint de diagnóstico

`GET /devices` devuelve las interfaces reales que Npcap/libpcap detecta,
y un flag `real_capture` (true/false) que indica si el binario corre con
captura real o con el simulador. Sirve para confirmar rápido si lo que
ves es tráfico real o de prueba.

`POST /start[?device=X]` ahora abre la interfaz de forma SINCRÓNICA: si
Npcap no está instalado, falta el SDK, el dispositivo no existe o falta
el permiso de Administrador/root, la respuesta HTTP trae el error real
(antes fallaba en silencio y la UI mostraba "capturando" sin datos). Si
no se especifica `device` (o se manda "any", que Npcap no soporta en
Windows), el backend autoselecciona la primera interfaz real disponible.

## Documentación completa

Para la especificación de requisitos, arquitectura, diseño y decisiones técnicas, ver [`docs/Documentacion.md`](docs/Documentacion.md).
