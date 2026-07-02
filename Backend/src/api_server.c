#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
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

#define MAX_EVENTS       500
#define REQUEST_BUF_SIZE 8192
#define DEFAULT_DEVICE   "any"


// Estado compartido: arreglo de ThreatEvent y su mutex.            
// Son estáticos y se inicializan automáticamente en memoria,       
// por lo que no requieren inicialización manual desde main.c.      


static ThreatEvent     g_events[MAX_EVENTS];
static int             g_event_count = 0;
static pthread_mutex_t g_events_mutex; 

static volatile int g_server_running = 0;  /* Estado del bucle del servidor */
static volatile int g_capturing      = 0;  /* Estado de la captura actual */
static pthread_t    g_capture_thread;
static char         g_capture_device[64] = DEFAULT_DEVICE;

static int g_listen_fd = -1;


// Captura: enlaza con data_reader con detector para analizar los paquetes  
// y guarda las amenazas encontradas en el arreglo compartido.      


void api_server_clear_events(void) {
    pthread_mutex_lock(&g_events_mutex);
    g_event_count = 0;
    pthread_mutex_unlock(&g_events_mutex);
}

void api_server_add_event(const ThreatEvent *event) {
    pthread_mutex_lock(&g_events_mutex);
    if (g_event_count < MAX_EVENTS) {
        g_events[g_event_count++] = *event;
    }
    /* Si el buffer se llena, se descartan los eventos nuevos. */
    pthread_mutex_unlock(&g_events_mutex);
}

static void on_packet_captured(NetworkPacket *packet) {
    ThreatEvent event;
    if (detector_analyze(packet, &event)) {
        api_server_add_event(&event);
    }
}

static void *capture_thread_main(void *arg) {
    (void)arg;
    /* Inicia y bloquea la ejecución hasta que se detenga la captura de paquetes. */
    data_reader_start_capture(g_capture_device, on_packet_captured);
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

static void handle_start(int client_fd, const HttpRequest *req) {
    if (strcmp(req->method, "POST") != 0) {
        send_response(client_fd, 405, "Method Not Allowed", "{\"error\":\"usar POST\"}");
        return;
    }
    if (g_capturing) {
        send_response(client_fd, 200, "OK", "{\"status\":\"ya estaba corriendo\"}");
        return;
    }

    char device[64];
    if (get_query_param(req->query, "device", device, sizeof(device))) {
        snprintf(g_capture_device, sizeof(g_capture_device), "%s", device);
    } else {
        snprintf(g_capture_device, sizeof(g_capture_device), "%s", DEFAULT_DEVICE);
    }

    g_capturing = 1;
    if (pthread_create(&g_capture_thread, NULL, capture_thread_main, NULL) != 0) {
        g_capturing = 0;
        send_response(client_fd, 500, "Internal Server Error", "{\"error\":\"no se pudo arrancar la captura\"}");
        return;
    }

    send_response(client_fd, 200, "OK", "{\"status\":\"capturando\"}");
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
    pthread_mutex_lock(&g_events_mutex);
    char *json = viewmodel_events_to_json(g_events, g_event_count);
    pthread_mutex_unlock(&g_events_mutex);

    send_response(client_fd, 200, "OK", json);
    free(json);
}

static void handle_alerts(int client_fd) {
    pthread_mutex_lock(&g_events_mutex);
    /* Se hace una copia y se ordena internamente para no alterar g_events. */
    char *json = viewmodel_alerts_to_json(g_events, g_event_count);
    pthread_mutex_unlock(&g_events_mutex);

    send_response(client_fd, 200, "OK", json);
    free(json);
}

static void handle_statistics(int client_fd) {
    pthread_mutex_lock(&g_events_mutex);
    char *json = viewmodel_statistics_to_json(g_events, g_event_count);
    pthread_mutex_unlock(&g_events_mutex);

    send_response(client_fd, 200, "OK", json);
    free(json);
}

static void handle_search(int client_fd, const HttpRequest *req) {
    char ip[IP_STR_LEN] = "";
    char port_str[16] = "";
    int has_ip = get_query_param(req->query, "ip", ip, sizeof(ip));
    int has_port = get_query_param(req->query, "port", port_str, sizeof(port_str));
    int port = has_port ? atoi(port_str) : -1;

    /* Filtra manualmente el arreglo completo para devolver una lista de eventos 
     * que coincidan con la IP o el puerto solicitados. */
    pthread_mutex_lock(&g_events_mutex);

    ThreatEvent matches[MAX_EVENTS];
    int match_count = 0;
    for (int i = 0; i < g_event_count; i++) {
        if (has_ip && strcmp(g_events[i].packet.src_ip, ip) != 0) continue;
        if (has_port && g_events[i].packet.dst_port != port) continue;
        matches[match_count++] = g_events[i];
    }
    char *json = viewmodel_events_to_json(matches, match_count);

    pthread_mutex_unlock(&g_events_mutex);

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
    } else if (strcmp(req->path, "/clear") == 0) {
        api_server_clear_events();
        send_response(client_fd, 200, "OK", "{\"status\":\"limpiado\"}");
    } else if (strcmp(req->path, "/search") == 0) {
        handle_search(client_fd, req);
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