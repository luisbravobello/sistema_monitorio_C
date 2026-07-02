#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
/* Necesario en Linux/macOS para que <string.h> declare strtok_r()
 * cuando se compila en modo estricto -std=c11. */
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #define close(s)      closesocket(s)
  #define pthread_t                HANDLE
  #define pthread_mutex_t          CRITICAL_SECTION
  #define PTHREAD_MUTEX_INITIALIZER {0}
  #define pthread_mutex_lock(m)    EnterCriticalSection(m)
  #define pthread_mutex_unlock(m)  LeaveCriticalSection(m)
  static inline int _win_pthread_create(HANDLE *t, void*(*fn)(void*), void*a){
      *t = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)fn,a,0,NULL);
      return *t ? 0 : -1;
  }
  #define pthread_create(t,a,fn,arg) _win_pthread_create(t,fn,arg)
  #define pthread_join(t,v)        WaitForSingleObject(t,INFINITE)
  /* Equivalente de strtok_r para entornos MinGW */
  static char *strtok_r(char *s, const char *d, char **p) {
      if (s) *p = s;
      if (!*p) return NULL;
      *p += strspn(*p, d);
      if (!**p) return NULL;
      char *tok = *p;
      *p += strcspn(*p, d);
      if (**p) { **p = '\0'; (*p)++; }
      return tok;
  }
  /* Operaciones de lectura y escritura para SOCKETs en Winsock */
  #define read(s,b,n)  recv(s,(char*)(b),(int)(n),0)
  #define write(s,b,n) send(s,(const char*)(b),(int)(n),0)
  /* Tipo ssize_t */
  typedef int ssize_t;
#else
  #include <unistd.h>
  #include <pthread.h>
  #include <sys/socket.h>
  #include <sys/select.h>
  #include <netinet/in.h>
#endif

#include "api_server.h"
#include "models.h"
#include "data_reader.h"
#include "detector.h"
#include "sort.h"
#include "viewmodel.h"

/*
 Servidor HTTP/ básico con sockets POSIX.
 Procesa las peticiones una por una de forma secuencial para el flujo de la UI.
 */

/* MAX_EVENTS ahora es grande porque guarda TODO el tráfico capturado,
 * no solo amenazas: con tráfico normal se llena rápido. Funciona como
 * buffer circular (ring buffer): al llenarse, sobreescribe los
 * registros más viejos y siempre conserva los más recientes. */
#define MAX_EVENTS       5000
/* Buffer INDEPENDIENTE solo para amenazas detectadas (SSH_BRUTE,
 * PORT_SCAN). Es necesario separarlo de g_events: con trafico real
 * (sobre todo en loopback, que es muy ruidoso) el ring buffer de
 * trafico normal se llena en segundos y sobreescribe las alertas ya
 * detectadas antes de que la UI llegue a mostrarlas. */
#define MAX_ALERTS       1000
#define REQUEST_BUF_SIZE 8192
#define MAX_DEVICES      32
/* Cadena vacía = autoseleccionar la primera interfaz real disponible.
 * "any" NO es válido en Npcap/Windows (solo funciona en Linux), por eso
 * ya no se usa como valor por defecto. */
#define DEFAULT_DEVICE   ""


// Estado compartido: arreglo de ThreatEvent y su mutex.            
// Son estáticos y se inicializan automáticamente en memoria,       
// por lo que no requieren inicialización manual desde main.c.      


static ThreatEvent     g_events[MAX_EVENTS];
static int             g_event_count = 0;  /* cuántos slots ocupados, hasta MAX_EVENTS */
static int             g_event_head  = 0;  /* próximo índice a escribir (ring buffer) */
static long            g_total_captured = 0; /* contador histórico real, no se resetea al llenar el buffer */

static ThreatEvent     g_alerts[MAX_ALERTS];
static int             g_alert_count = 0;
static int             g_alert_head  = 0;

static pthread_mutex_t g_events_mutex; 

static volatile int g_server_running = 0;  /* Estado del bucle del servidor */
static volatile int g_capturing      = 0;  /* Estado de la captura actual */
static pthread_t    g_capture_thread;
static char         g_capture_device[DR_DEVICE_NAME_LEN] = DEFAULT_DEVICE;

static int g_listen_fd = -1;


// Captura: enlaza con data_reader con detector para analizar los paquetes  
// y guarda las amenazas encontradas en el arreglo compartido.      


void api_server_clear_events(void) {
    pthread_mutex_lock(&g_events_mutex);
    g_event_count    = 0;
    g_event_head     = 0;
    g_total_captured = 0;
    g_alert_count    = 0;
    g_alert_head     = 0;
    pthread_mutex_unlock(&g_events_mutex);
}

/* Debe llamarse con g_events_mutex ya bloqueado. */
static void add_alert_locked(const ThreatEvent *event) {
    g_alerts[g_alert_head] = *event;
    g_alert_head = (g_alert_head + 1) % MAX_ALERTS;
    if (g_alert_count < MAX_ALERTS) g_alert_count++;
}

void api_server_add_event(const ThreatEvent *event) {
    pthread_mutex_lock(&g_events_mutex);
    g_events[g_event_head] = *event;
    g_event_head = (g_event_head + 1) % MAX_EVENTS;
    if (g_event_count < MAX_EVENTS) g_event_count++;
    /* Al llenarse, sobreescribe el mas viejo (ring buffer) en vez de
     * descartar lo nuevo: asi la UI siempre ve el trafico mas reciente. */
    g_total_captured++;

    /* Las amenazas reales ademas se guardan en su propio buffer, que
     * NO se ve afectado por el volumen de trafico normal. */
    if (strcmp(event->threat_type, "TRAFICO") != 0) {
        add_alert_locked(event);
    }
    pthread_mutex_unlock(&g_events_mutex);
}

/* Copia una "foto" en orden cronologico (del mas viejo al mas nuevo) del
 * ring buffer de alertas. Debe llamarse con g_events_mutex bloqueado. */
static int snapshot_alerts_locked(ThreatEvent *out, int max_out) {
    int n     = g_alert_count;
    int start = (g_alert_count < MAX_ALERTS) ? 0 : g_alert_head;
    int count = (n < max_out) ? n : max_out;
    int skip  = n - count;
    for (int i = 0; i < count; i++) {
        int idx = (start + skip + i) % MAX_ALERTS;
        out[i] = g_alerts[idx];
    }
    return count;
}

/* Copia una "foto" en orden cronologico (del mas viejo al mas nuevo) del
 * ring buffer hacia un arreglo lineal comun, para que el resto del codigo
 * (JSON, busqueda, estadisticas) no tenga que lidiar con el wrap-around.
 * Debe llamarse con g_events_mutex ya bloqueado por el caller. */
static int snapshot_events_locked(ThreatEvent *out, int max_out) {
    int n     = g_event_count;
    int start = (g_event_count < MAX_EVENTS) ? 0 : g_event_head;
    int count = (n < max_out) ? n : max_out;
    int skip  = n - count;  /* si hay que recortar, nos quedamos con los mas recientes */
    for (int i = 0; i < count; i++) {
        int idx = (start + skip + i) % MAX_EVENTS;
        out[i] = g_events[idx];
    }
    return count;
}

static void on_packet_captured(NetworkPacket *packet) {
    ThreatEvent event;
    if (!detector_analyze(packet, &event)) {
        /* Trafico normal, sin amenaza detectada: se registra igual para
         * que la UI pueda mostrar TODO el trafico capturado, no solo
         * las amenazas. La pestana de Alertas sigue mostrando solo lo
         * confirmado por el detector (ver handle_alerts/confirmed). */
        event.packet = *packet;
        strncpy(event.threat_type, "TRAFICO", sizeof(event.threat_type) - 1);
        event.threat_type[sizeof(event.threat_type) - 1] = '\0';
        event.severity  = 0;
        event.confirmed = 0;
    }
    api_server_add_event(&event);
}

static void *capture_thread_main(void *arg) {
    (void)arg;
    /* El dispositivo ya fue abierto de forma sincrónica en handle_start();
     * aquí solo corremos el bucle bloqueante hasta que se detenga. */
    data_reader_run_capture(on_packet_captured);
    g_capturing = 0;
    return NULL;
}

// HTTP: procesamiento básico de la petición y sus parámetros. 

typedef struct {
    char method[8];
    char path[512];
    char query[256];
} HttpRequest;

/* Decodifica caracteres especiales (%XX y '+') de la URL directamente en la cadena. */
static void url_decode(char *s) {
    char *src = s, *dst = s;
    while (*src) {
        if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else if (*src == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            char hex[3] = { src[1], src[2], '\0' };
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static int get_query_param(const char *query, const char *key, char *out, size_t out_size) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", query);

    char *saveptr = NULL;
    char *pair = strtok_r(buf, "&", &saveptr);
    size_t keylen = strlen(key);

    while (pair) {
        if (strncmp(pair, key, keylen) == 0 && pair[keylen] == '=') {
            snprintf(out, out_size, "%s", pair + keylen + 1);
            url_decode(out);
            return 1;
        }
        pair = strtok_r(NULL, "&", &saveptr);
    }
    return 0;
}

static int parse_request_line(const char *raw, HttpRequest *req) {
    char path_and_query[512];
    if (sscanf(raw, "%7s %511s", req->method, path_and_query) != 2) {
        return -1;
    }
    char *qmark = strchr(path_and_query, '?');
    if (qmark) {
        *qmark = '\0';
        snprintf(req->query, sizeof(req->query), "%s", qmark + 1);
    } else {
        req->query[0] = '\0';
    }
    snprintf(req->path, sizeof(req->path), "%s", path_and_query);
    return 0;
}

static void send_response(int client_fd, int status, const char *status_text, const char *body) {
    char header[256];
    int body_len = (int)strlen(body);
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, status_text, body_len);
    write(client_fd, header, (size_t)header_len);
    write(client_fd, body, (size_t)body_len);
}

/*  */
/* Controladores para cada endpoint según docs/API_CONTRACT.md.     */
/*  */

/* Escapa comillas y barras invertidas para insertar texto dinámico
 * dentro de un JSON de forma segura. Es indispensable en Windows:
 * los nombres de interfaz de Npcap son del tipo "\Device\NPF_{GUID}",
 * y sin escapar esas barras invertidas el JSON queda inválido y
 * revienta al parsearlo del lado de la UI en Python. */
static void json_escape(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j + 2 < out_size; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '\\' || c == '"') {
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c == '\n') {
            out[j++] = '\\'; out[j++] = 'n';
        } else if (c == '\r') {
            out[j++] = '\\'; out[j++] = 'r';
        } else if (c == '\t') {
            out[j++] = '\\'; out[j++] = 't';
        } else if (c < 0x20) {
            /* caracteres de control: se omiten */
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

static void handle_start(int client_fd, const HttpRequest *req) {
    if (strcmp(req->method, "POST") != 0) {
        send_response(client_fd, 405, "Method Not Allowed", "{\"error\":\"usar POST\"}");
        return;
    }
    if (g_capturing) {
        send_response(client_fd, 200, "OK", "{\"status\":\"ya estaba corriendo\"}");
        return;
    }

    char device[DR_DEVICE_NAME_LEN];
    if (get_query_param(req->query, "device", device, sizeof(device))) {
        snprintf(g_capture_device, sizeof(g_capture_device), "%s", device);
    } else {
        snprintf(g_capture_device, sizeof(g_capture_device), "%s", DEFAULT_DEVICE);
    }

    char errbuf[DR_ERRBUF_LEN];
    char device_used[DR_DEVICE_NAME_LEN];
    if (data_reader_open_capture(g_capture_device, errbuf, sizeof(errbuf),
                                  device_used, sizeof(device_used)) != 0) {
        char errbuf_esc[DR_ERRBUF_LEN * 2];
        json_escape(errbuf, errbuf_esc, sizeof(errbuf_esc));
        char body[sizeof(errbuf_esc) + 64];
        snprintf(body, sizeof(body), "{\"error\":\"%s\"}", errbuf_esc);
        send_response(client_fd, 500, "Internal Server Error", body);
        return;
    }
    snprintf(g_capture_device, sizeof(g_capture_device), "%s", device_used);

    g_capturing = 1;
    if (pthread_create(&g_capture_thread, NULL, capture_thread_main, NULL) != 0) {
        g_capturing = 0;
        data_reader_stop_capture();
        send_response(client_fd, 500, "Internal Server Error", "{\"error\":\"no se pudo arrancar la captura\"}");
        return;
    }

    char device_esc[DR_DEVICE_NAME_LEN * 2];
    json_escape(g_capture_device, device_esc, sizeof(device_esc));
    char body[sizeof(device_esc) + 64];
    snprintf(body, sizeof(body),
             "{\"status\":\"capturando\",\"device\":\"%s\",\"real_capture\":%s}",
             device_esc, data_reader_has_real_capture() ? "true" : "false");
    send_response(client_fd, 200, "OK", body);
}

static void handle_devices(int client_fd) {
    char names[MAX_DEVICES][DR_DEVICE_NAME_LEN];
    char descs[MAX_DEVICES][DR_DEVICE_DESC_LEN];
    char errbuf[DR_ERRBUF_LEN];
    errbuf[0] = '\0';

    int n = data_reader_list_devices(names, descs, MAX_DEVICES, errbuf, sizeof(errbuf));

    char body[8192];
    int off = snprintf(body, sizeof(body),
                        "{\"real_capture\":%s,\"devices\":[",
                        data_reader_has_real_capture() ? "true" : "false");
    for (int i = 0; i < n && off < (int)sizeof(body) - 1; i++) {
        char name_esc[DR_DEVICE_NAME_LEN * 2];
        char desc_esc[DR_DEVICE_DESC_LEN * 2];
        json_escape(names[i], name_esc, sizeof(name_esc));
        json_escape(descs[i], desc_esc, sizeof(desc_esc));
        off += snprintf(body + off, sizeof(body) - off,
                         "%s{\"name\":\"%s\",\"description\":\"%s\"}",
                         (i > 0 ? "," : ""), name_esc, desc_esc);
    }
    off += snprintf(body + off, sizeof(body) - off, "]");
    if (n <= 0 && errbuf[0]) {
        char errbuf_esc[DR_ERRBUF_LEN * 2];
        json_escape(errbuf, errbuf_esc, sizeof(errbuf_esc));
        off += snprintf(body + off, sizeof(body) - off, ",\"error\":\"%s\"", errbuf_esc);
    }
    snprintf(body + off, sizeof(body) - off, "}");

    send_response(client_fd, 200, "OK", body);
}

static void handle_stop(int client_fd, const HttpRequest *req) {
    if (strcmp(req->method, "POST") != 0) {
        send_response(client_fd, 405, "Method Not Allowed", "{\"error\":\"usar POST\"}");
        return;
    }
    if (g_capturing) {
        data_reader_stop_capture();
        pthread_join(g_capture_thread, NULL);
        g_capturing = 0;
    }
    send_response(client_fd, 200, "OK", "{\"status\":\"detenido\"}");
}

static void handle_events(int client_fd) {
    ThreatEvent *snap = malloc((size_t)MAX_EVENTS * sizeof(ThreatEvent));
    if (!snap) { send_response(client_fd, 500, "Internal Server Error", "{\"error\":\"sin memoria\"}"); return; }

    pthread_mutex_lock(&g_events_mutex);
    int n = snapshot_events_locked(snap, MAX_EVENTS);
    pthread_mutex_unlock(&g_events_mutex);

    char *json = viewmodel_events_to_json(snap, n);
    free(snap);
    send_response(client_fd, 200, "OK", json);
    free(json);
}

static void handle_alerts(int client_fd) {
    ThreatEvent *snap = malloc((size_t)MAX_ALERTS * sizeof(ThreatEvent));
    if (!snap) { send_response(client_fd, 500, "Internal Server Error", "{\"error\":\"sin memoria\"}"); return; }

    pthread_mutex_lock(&g_events_mutex);
    int n = snapshot_alerts_locked(snap, MAX_ALERTS);
    pthread_mutex_unlock(&g_events_mutex);

    /* viewmodel_alerts_to_json ordena y filtra confirmed==1 internamente. */
    char *json = viewmodel_alerts_to_json(snap, n);
    free(snap);
    send_response(client_fd, 200, "OK", json);
    free(json);
}

static void handle_statistics(int client_fd) {
    ThreatEvent *snap = malloc((size_t)MAX_EVENTS * sizeof(ThreatEvent));
    if (!snap) { send_response(client_fd, 500, "Internal Server Error", "{\"error\":\"sin memoria\"}"); return; }

    pthread_mutex_lock(&g_events_mutex);
    int n = snapshot_events_locked(snap, MAX_EVENTS);
    long total_captured = g_total_captured;
    pthread_mutex_unlock(&g_events_mutex);

    char *json = viewmodel_statistics_to_json(snap, n);
    free(snap);
    /* Inyecta el contador historico real (no limitado al tamano del ring
     * buffer) reemplazando el cierre del objeto JSON generado arriba. */
    size_t json_len = strlen(json);
    char *body = malloc(json_len + 64);
    if (body && json_len > 0 && json[json_len - 1] == '}') {
        snprintf(body, json_len + 64, "%.*s,\"total_capturado_historico\":%ld}",
                 (int)(json_len - 1), json, total_captured);
        send_response(client_fd, 200, "OK", body);
        free(body);
    } else {
        send_response(client_fd, 200, "OK", json);
        free(body);
    }
    free(json);
}

/* Inyecta un evento de amenaza "de mentira" directo en el backend, sin
 * depender de que pase trafico real por la red. Sirve para probar el
 * flujo de Alertas desde la UI con un click, sin lidiar con interfaces,
 * gateways, ni PowerShell. ?type=ssh_brute (default) o ?type=port_scan */
static void handle_simulate(int client_fd, const HttpRequest *req) {
    if (strcmp(req->method, "POST") != 0) {
        send_response(client_fd, 405, "Method Not Allowed", "{\"error\":\"usar POST\"}");
        return;
    }

    char type[32] = "ssh_brute";
    get_query_param(req->query, "type", type, sizeof(type));

    ThreatEvent event;
    memset(&event, 0, sizeof(event));
    snprintf(event.packet.src_ip, IP_STR_LEN, "%s", "203.0.113.55" /* IP de prueba (RFC 5737, no enrutable) */);
    snprintf(event.packet.dst_ip, IP_STR_LEN, "%s", "192.168.1.1");
    snprintf(event.packet.protocol, PROTO_STR_LEN, "%s", "TCP");
    event.packet.size      = 60;
    event.packet.timestamp = time(NULL);
    event.packet.src_port  = 51234;

    if (strcmp(type, "port_scan") == 0) {
        event.packet.dst_port = 80;
        snprintf(event.threat_type, THREAT_TYPE_LEN, "%s", "PORT_SCAN");
        event.severity  = 3;
        event.confirmed = 0;  /* mismo criterio que el detector real: PORT_SCAN queda como sospecha */
    } else {
        snprintf(type, sizeof(type), "%s", "ssh_brute");
        event.packet.dst_port = 22;
        snprintf(event.threat_type, THREAT_TYPE_LEN, "%s", "SSH_BRUTE");
        event.severity  = 4;
        event.confirmed = 1;
    }

    api_server_add_event(&event);

    char body[128];
    snprintf(body, sizeof(body), "{\"status\":\"simulado\",\"tipo\":\"%s\"}", event.threat_type);
    send_response(client_fd, 200, "OK", body);
}

static void handle_search(int client_fd, const HttpRequest *req) {
    char ip[IP_STR_LEN] = "";
    char port_str[16] = "";
    int has_ip = get_query_param(req->query, "ip", ip, sizeof(ip));
    int has_port = get_query_param(req->query, "port", port_str, sizeof(port_str));
    int port = has_port ? atoi(port_str) : -1;

    ThreatEvent *snap = malloc((size_t)MAX_EVENTS * sizeof(ThreatEvent));
    ThreatEvent *matches = malloc((size_t)MAX_EVENTS * sizeof(ThreatEvent));
    if (!snap || !matches) {
        free(snap); free(matches);
        send_response(client_fd, 500, "Internal Server Error", "{\"error\":\"sin memoria\"}");
        return;
    }

    pthread_mutex_lock(&g_events_mutex);
    int n = snapshot_events_locked(snap, MAX_EVENTS);
    pthread_mutex_unlock(&g_events_mutex);

    int match_count = 0;
    for (int i = 0; i < n; i++) {
        if (has_ip && strcmp(snap[i].packet.src_ip, ip) != 0) continue;
        if (has_port && snap[i].packet.dst_port != port) continue;
        matches[match_count++] = snap[i];
    }
    char *json = viewmodel_events_to_json(matches, match_count);
    free(snap); free(matches);

    send_response(client_fd, 200, "OK", json);
    free(json);
}

static void route_request(int client_fd, const HttpRequest *req) {
    if (strcmp(req->path, "/start") == 0) {
        handle_start(client_fd, req);
    } else if (strcmp(req->path, "/stop") == 0) {
        handle_stop(client_fd, req);
    } else if (strcmp(req->path, "/events") == 0) {
        handle_events(client_fd);
    } else if (strcmp(req->path, "/alerts") == 0) {
        handle_alerts(client_fd);
    } else if (strcmp(req->path, "/statistics") == 0) {
        handle_statistics(client_fd);
    } else if (strcmp(req->path, "/devices") == 0) {
        handle_devices(client_fd);
    } else if (strcmp(req->path, "/clear") == 0) {
        api_server_clear_events();
        send_response(client_fd, 200, "OK", "{\"status\":\"limpiado\"}");
    } else if (strcmp(req->path, "/search") == 0) {
        handle_search(client_fd, req);
    } else if (strcmp(req->path, "/simulate") == 0) {
        handle_simulate(client_fd, req);
    } else {
        send_response(client_fd, 404, "Not Found", "{\"error\":\"ruta desconocida\"}");
    }
}

static void handle_client(int client_fd) {
    char buffer[REQUEST_BUF_SIZE];
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buffer[n] = '\0';

    char *line_end = strstr(buffer, "\r\n");
    size_t line_len = line_end ? (size_t)(line_end - buffer) : strlen(buffer);
    if (line_len >= sizeof(buffer)) line_len = sizeof(buffer) - 1;

    char request_line[512];
    snprintf(request_line, sizeof(request_line), "%.*s", (int)line_len, buffer);

    HttpRequest req;
    if (parse_request_line(request_line, &req) != 0) {
        send_response(client_fd, 400, "Bad Request", "{\"error\":\"request invalido\"}");
        close(client_fd);
        return;
    }

    route_request(client_fd, &req);
    close(client_fd);
}

/* ---------------------------------------------------------------- */
/* Ciclo principal: acepta conexiones usando un timeout para        */
/* verificar g_server_running y poder cerrarse de forma segura.     */
/* ---------------------------------------------------------------- */

void api_server_start(int port) {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    InitializeCriticalSection(&g_events_mutex);
#endif
    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        perror("socket");
        return;
    }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((unsigned short)port);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(g_listen_fd);
        g_listen_fd = -1;
        return;
    }

    if (listen(g_listen_fd, 16) < 0) {
        perror("listen");
        close(g_listen_fd);
        g_listen_fd = -1;
        return;
    }

    g_server_running = 1;

    while (g_server_running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(g_listen_fd, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int ready = select(g_listen_fd + 1, &readfds, NULL, NULL, &timeout);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ready == 0) continue; /* Timeout: vuelve a comprobar si el servidor sigue corriendo */

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(g_listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        handle_client(client_fd);
    }

    close(g_listen_fd);
    g_listen_fd = -1;
}

void api_server_stop(void) {
    g_server_running = 0;
    if (g_capturing) {
        data_reader_stop_capture();
    }
}