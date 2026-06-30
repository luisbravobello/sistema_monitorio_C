# Sistema de Monitoreo de Amenazas de Red

Sistema de monitoreo de tráfico de red en tiempo real, capaz de detectar amenazas como escaneos de puertos y ataques de fuerza bruta por SSH. El proyecto está dividido en dos capas: un **backend en C** que actúa como servidor HTTP, y una **UI en Python** que consume su API REST.

---

## Autores

| Rol | Nombre |
|-----|--------|
| Lógica / Backend | Luis Alejandro Bravo Bello |
| Interfaz de Usuario (UI) | Ronald Alberto Reyes Sánchez |

---

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

## Búsqueda y ordenamiento

**Búsqueda (`search.c`)**
- `search_linear_by_ip` — búsqueda secuencial por IP de origen.
- `search_binary_by_timestamp` — búsqueda binaria por timestamp (requiere el arreglo ordenado previamente con `sort_by_timestamp`).

**Ordenamiento (`sort.c`)**
- `sort_by_timestamp` — del evento más antiguo al más reciente.
- `sort_by_severity` — del más crítico al más leve.

---

## Formato de log

Para cargar paquetes desde archivo, cada línea debe seguir este formato:

```
timestamp src_ip src_port dst_ip dst_port protocol size
```

Ejemplo:
```
1700000000 192.168.1.10 54321 10.0.0.1 22 TCP 64
1700000005 192.168.1.10 54322 10.0.0.1 22 TCP 64
# Las líneas que empiezan con # o vacías se ignoran
```

---

## Compilación

### Requisitos

- GCC (MinGW en Windows) o cualquier compilador C11
- *(Opcional)* `libpcap` para captura en vivo real

### En Windows (MinGW)

```bash
gcc -std=c11 -Iinclude src/*.c -o monitor -lws2_32
```

Con pcap:

```bash
gcc -std=c11 -Iinclude -DHAVE_PCAP src/*.c -o monitor -lws2_32 -lwpcap
```

### En Linux / macOS

```bash
gcc -std=c11 -Iinclude src/*.c -o monitor -lpthread
```

Con pcap:

```bash
gcc -std=c11 -Iinclude -DHAVE_PCAP src/*.c -o monitor -lpthread -lpcap
```

---

## Ejecución

```bash
# Backend
./monitor
# → Monitor de Amenazas — servidor escuchando en http://localhost:8080

# UI (en otra terminal)
cd UI
pip install -r requirements.txt
python main.py
```

---

## Dependencias externas

| Componente | Dependencia | Obligatoria |
|------------|-------------|-------------|
| Backend C | `libpcap` / `WinPcap` | No (hay simulador interno) |
| Backend C | `pthreads` / `Winsock2` | Sí |
| UI Python | Ver `UI/requirements.txt` | Sí |

> **Nota:** Si `libpcap` no está instalada, el backend activa automáticamente un simulador de paquetes para pruebas sin necesidad de privilegios de red.
