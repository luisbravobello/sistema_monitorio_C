# Especificación de Requisitos de Software (ERS)
## Sistema de Monitoreo de Amenazas de Red

**Documento elaborado conforme al estándar IEEE 830**

| Rol | Nombre |
|-----|--------|
| Lógica / Backend | Luis Alejandro Bravo Bello |
| Interfaz de Usuario (UI) | Ronald Alberto Reyes Sánchez |

---

## 1. Introducción

### 1.1 Propósito

El propósito de este documento es especificar de forma clara y estructurada los requisitos, el diseño general y el funcionamiento del **Sistema de Monitoreo de Amenazas de Red**, con el fin de servir como referencia técnica para su desarrollo, mantenimiento y evaluación académica. Está dirigido a los desarrolladores del proyecto, a los evaluadores del curso y a cualquier persona que necesite comprender o dar continuidad al sistema.

### 1.2 Alcance del sistema

El sistema permite capturar y/o leer tráfico de red, analizarlo mediante un motor de detección de amenazas, y exponer los resultados a través de una API REST consumida por una interfaz gráfica. El proyecto está compuesto por dos capas: un **backend en C** (servidor HTTP, motor de detección, algoritmos de ordenamiento y búsqueda) y una **UI en Python** que consume dicha API.

El sistema identifica dos tipos de amenazas —**escaneo de puertos (PORT_SCAN)** y **fuerza bruta por SSH (SSH_BRUTE)**— y aplica algoritmos de ordenamiento por inserción y de búsqueda lineal/binaria sobre los eventos detectados. No contempla persistencia en base de datos, autenticación, cifrado ni despliegue distribuido (ver sección 7, Mejoras futuras).

### 1.3 Definiciones, siglas y abreviaturas

| Término | Definición |
|---|---|
| API REST | Interfaz de programación de aplicaciones basada en el protocolo HTTP |
| ERS | Especificación de Requisitos de Software |
| PORT_SCAN | Tipo de amenaza: escaneo de múltiples puertos desde una misma IP |
| SSH_BRUTE | Tipo de amenaza: intento de fuerza bruta contra el puerto 22 (SSH) |
| UI | Interfaz de usuario (User Interface) |
| JSON | JavaScript Object Notation, formato de intercambio de datos |
| pcap | Librería de captura de paquetes de red (libpcap / WinPcap) |

### 1.4 Referencias

- IEEE Std 830-1998, *IEEE Recommended Practice for Software Requirements Specifications*.
- Documentación interna del proyecto: código fuente en `Backend/src` y `UI/`.

### 1.5 Visión general del documento

Este documento se organiza siguiendo la estructura general de IEEE 830: la sección 2 presenta una descripción general del producto; la sección 3 detalla los requisitos funcionales y no funcionales; la sección 4 describe el diseño y la arquitectura del sistema; la sección 5 resume las decisiones técnicas relevantes; la sección 6 describe la compilación y ejecución; y la sección 7 plantea posibles mejoras futuras.

---

## 2. Descripción general

### 2.1 Perspectiva del producto

El sistema es una aplicación independiente compuesta por dos módulos que se comunican mediante HTTP en `localhost:8080`. No depende de sistemas externos salvo, opcionalmente, `libpcap` para la captura real de tráfico.

```
┌─────────────────────┐       HTTP REST         ┌────────────────────────┐
│      UI Python       │ ◄─────────────────────► │      Backend C         │
│  (main_window.py)    │     localhost:8080      │    (api_server.c)      │
└─────────────────────┘                          └───────────┬────────────┘
                                                               │
                              ┌────────────────────────────────┼──────────────────────┐
                              ▼                                ▼                       ▼
                       data_reader.c                    detector.c              viewmodel.c
                    (pcap / log file)             (PORT_SCAN, SSH_BRUTE)      (JSON responses)
```

### 2.2 Funciones del producto

- Captura de tráfico de red en vivo o lectura desde archivo de log.
- Detección de amenazas mediante análisis por ventana de tiempo.
- Ordenamiento de eventos por timestamp o por severidad.
- Búsqueda de eventos por IP de origen o por timestamp.
- Exposición de toda la funcionalidad mediante una API REST.
- Visualización de eventos, alertas y estadísticas desde una interfaz gráfica.

### 2.3 Características de los usuarios

El sistema está pensado para un usuario técnico único (analista o estudiante) que ejecuta el backend y la UI en la misma máquina, con fines de prueba, aprendizaje o demostración académica.

### 2.4 Restricciones

- El servidor HTTP no implementa autenticación ni cifrado (HTTP plano).
- El almacenamiento de eventos es en memoria; no persiste entre ejecuciones.
- El backend atiende las peticiones HTTP de forma secuencial (un cliente a la vez).
- Los tamaños de los buffers internos son fijos (ver sección 5).

### 2.5 Suposiciones y dependencias

- Se asume un entorno de red local (`localhost`) de un solo usuario.
- La captura real de tráfico depende de tener `libpcap`/`WinPcap` instalada y permisos adecuados; en caso contrario, el sistema recurre a un simulador interno.

---

## 3. Requisitos específicos

### 3.1 Requisitos funcionales (RF)

| ID | Requisito |
|----|-----------|
| RF-01 | El sistema debe permitir iniciar la captura de tráfico en una interfaz de red especificada. |
| RF-02 | El sistema debe permitir detener la captura de tráfico en curso. |
| RF-03 | El sistema debe permitir cargar paquetes de red desde un archivo de log con formato predefinido. |
| RF-04 | El sistema debe detectar eventos de tipo `PORT_SCAN` cuando una misma IP acceda a 5 o más puertos distintos en una ventana de 10 segundos. |
| RF-05 | El sistema debe detectar eventos de tipo `SSH_BRUTE` cuando una misma IP realice 4 o más conexiones al puerto 22 en una ventana de 10 segundos. |
| RF-06 | El sistema debe ordenar los eventos detectados por timestamp (ascendente) mediante ordenamiento por inserción. |
| RF-07 | El sistema debe ordenar los eventos detectados por severidad (descendente) mediante ordenamiento por inserción. |
| RF-08 | El sistema debe permitir buscar un evento por dirección IP de origen mediante búsqueda lineal. |
| RF-09 | El sistema debe permitir buscar un evento por timestamp mediante búsqueda binaria, requiriendo el arreglo previamente ordenado. |
| RF-10 | El sistema debe exponer los eventos, alertas y estadísticas mediante una API REST en formato JSON. |
| RF-11 | La UI debe consumir la API REST y presentar los eventos, alertas y estadísticas al usuario. |

### 3.2 Requisitos no funcionales (RNF)

| ID | Requisito |
|----|-----------|
| RNF-01 | El backend debe compilar y ejecutarse tanto en Windows como en Linux/macOS a partir del mismo código fuente. |
| RNF-02 | El backend no debe depender de librerías externas obligatorias (solo GCC estándar); `libpcap` es opcional. |
| RNF-03 | El acceso concurrente al arreglo de eventos debe estar protegido mediante mecanismos de exclusión mutua (mutex). |
| RNF-04 | El sistema debe poder operar sin captura real de red, mediante un simulador interno, para fines de prueba. |
| RNF-05 | El formato de intercambio entre backend y UI debe ser JSON, sobre HTTP. |

### 3.3 Interfaces externas — API REST

El servidor escucha en `http://localhost:8080`.

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/start?device=X` | Inicia la captura de paquetes en la interfaz `X` |
| `POST` | `/stop` | Detiene la captura |
| `GET` | `/events` | Retorna todos los eventos detectados (JSON) |
| `GET` | `/alerts` | Retorna solo las amenazas confirmadas, ordenadas por severidad (JSON) |
| `GET` | `/statistics` | Resumen general: cantidad de paquetes, tipos de ataque, niveles de severidad (JSON) |
| `GET` | `/search?ip=&port=` | Filtra eventos por IP de origen o puerto |

### 3.4 Requisitos de datos — modelos

**`NetworkPacket`** — paquete de red interceptado (en vivo o desde log):

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `src_ip` | `char[46]` | IP de origen (IPv4 o IPv6) |
| `dst_ip` | `char[46]` | IP de destino |
| `src_port` | `int` | Puerto de origen |
| `dst_port` | `int` | Puerto de destino |
| `protocol` | `char[8]` | TCP, UDP o ICMP |
| `size` | `int` | Tamaño del paquete en bytes |
| `timestamp` | `time_t` | Marca de tiempo Unix |

**`ThreatEvent`** — alerta generada por el detector:

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `packet` | `NetworkPacket` | Paquete que disparó la alerta |
| `threat_type` | `char[32]` | `PORT_SCAN` o `SSH_BRUTE` |
| `severity` | `int` | Nivel del 1 (Bajo) al 5 (Crítico) |
| `confirmed` | `int` | `0` = Sospecha, `1` = Confirmado |

**Formato de log** (una línea por paquete):

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

## 4. Diseño del sistema

### 4.1 Estructura del proyecto

```
sistema_monitorio_C/
├── UI/
│   ├── main.py              Punto de entrada de la interfaz
│   ├── main_window.py       Ventana principal
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
        ├── sort.c           Ordenamiento por inserción (timestamp y severidad)
        └── viewmodel.c      Conversión de ThreatEvent[] a JSON
```

### 4.2 Motor de detección

El detector (`detector.c`) usa una **ventana deslizante de 10 segundos** sobre un historial circular de 256 entradas:

| Amenaza | Condición | Severidad | Estado |
|---------|-----------|-----------|--------|
| `PORT_SCAN` | ≥ 5 puertos distintos en 10 s | 3 | Sospecha |
| `SSH_BRUTE` | ≥ 4 conexiones al puerto 22 en 10 s | 4 | Confirmado |

### 4.3 Algoritmos de ordenamiento y búsqueda

**Ordenamiento (`sort.c`)**
- `sort_by_timestamp` — ordenamiento por inserción, del evento más antiguo al más reciente.
- `sort_by_severity` — ordenamiento por inserción, del más crítico al más leve.

**Búsqueda (`search.c`)**
- `search_linear_by_ip` — búsqueda secuencial por IP de origen.
- `search_binary_by_timestamp` — búsqueda binaria por timestamp (requiere el arreglo previamente ordenado con `sort_by_timestamp`).

### 4.4 Flujo de carga de datos

```
Origen del paquete            Procesamiento                         Salida
──────────────────      ─────────────────────────      ─────────────────────────

 libpcap (interfaz)  ┐
                     ├──►  NetworkPacket  ──► detector_analyze() ──►  ThreatEvent
 Simulador interno   ┘         (crudo)         (ventana de 10 s)      (si hay amenaza)

 Archivo de log ────────►  NetworkPacket
   (data_reader_from_log)
```

1. **Captura en vivo:** si el backend fue compilado con `-DHAVE_PCAP` y `libpcap` está disponible, se abre la interfaz indicada y cada paquete capturado se convierte en un `NetworkPacket` (IP origen/destino, protocolo, puertos).
2. **Simulador interno:** si no hay `libpcap`, se activa automáticamente un generador de tráfico de prueba (~5 paquetes/segundo).
3. **Lectura desde log:** se procesa línea por línea, descartando comentarios, líneas vacías o mal formadas.
4. **Análisis:** cada `NetworkPacket` se envía a `detector_analyze`, que evalúa la ventana de tiempo de 10 s para la IP correspondiente.
5. **Registro:** si se confirma una amenaza, el `ThreatEvent` se agrega al arreglo global de eventos (protegido por mutex) y queda disponible para la API.

---

## 5. Decisiones de diseño

- **Sockets nativos sin frameworks:** el servidor HTTP se implementó sobre sockets POSIX/Winsock para no depender de librerías externas obligatorias.
- **Simulador de tráfico:** permite probar el sistema sin permisos de red ni hardware físico, activándose automáticamente si no hay `libpcap`.
- **Estructuras de tamaño fijo:** el historial del detector (256 entradas) y el arreglo de eventos (500 entradas) son estáticos, lo que simplifica la gestión de memoria y la sincronización, a costa de un límite de capacidad.
- **Concurrencia con mutex:** el acceso al arreglo compartido de eventos está protegido con `pthread_mutex_t`, ya que la captura corre en un hilo separado del servidor HTTP.
- **Servidor secuencial:** las peticiones HTTP se atienden una a la vez, ya que el sistema está pensado para un solo cliente (la UI local).

---

## 6. Compilación y ejecución

### 6.1 Requisitos

- GCC (MinGW en Windows) o cualquier compilador C11.
- *(Opcional)* `libpcap` para captura en vivo real.

### 6.2 Compilación en Windows (MinGW)

```bash
gcc -std=c11 -Iinclude src/*.c -o monitor.exe -lws2_32
```

Con soporte de captura en vivo (pcap):

```bash
gcc -std=c11 -Iinclude -DHAVE_PCAP src/*.c -o monitor.exe -lws2_32 -lwpcap
```

### 6.3 Ejecución

```bash
# Backend
./monitor
# → Monitor de Amenazas — servidor escuchando en http://localhost:8080

# UI (en otra terminal)
cd UI
pip install -r requirements.txt
python main.py
```

### 6.5 Dependencias externas

| Componente | Dependencia | Obligatoria |
|------------|-------------|-------------|
| Backend C | `libpcap` / `WinPcap` | No (hay simulador interno) |
| Backend C | `pthreads` / `Winsock2` | Sí |
| UI Python | Ver `UI/requirements.txt` | Sí |

---

## 7. Posibles mejoras futuras

- **Persistencia de datos:** almacenamiento en disco o base de datos (por ejemplo, SQLite) para conservar el historial entre reinicios.
- **Autenticación y cifrado:** tokens de acceso y HTTPS para exponer la API más allá de `localhost` de forma segura.
- **Umbrales de detección configurables:** exponer `WINDOW_SECS`, `PORTSCAN_THRESHOLD` y `SSHBRUTE_THRESHOLD` como parámetros externos.
- **Más tipos de amenazas:** extender el motor de detección a patrones adicionales (DoS por volumen, listas negras de IP).
- **Servidor HTTP concurrente:** atender múltiples clientes mediante pool de hilos o `select`/`epoll`.
- **Estructuras dinámicas:** reemplazar los límites fijos (`MAX_EVENTS`, `HISTORY_SIZE`) por estructuras redimensionables.
- **Algoritmos más eficientes:** sustituir el ordenamiento por inserción (O(n²)) por uno de complejidad O(n log n) para grandes volúmenes de eventos.
- **Pruebas automatizadas:** pruebas unitarias sobre los módulos de ordenamiento, búsqueda y detección.
- **Notificaciones en tiempo real:** WebSockets o Server-Sent Events para alertar al usuario en el momento de la detección.
