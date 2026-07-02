#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
/* Necesario en Linux/macOS para que <pcap.h> pueda usar u_char/u_short/u_int
 * (tipos BSD) cuando se compila en modo estricto -std=c11. En Windows esto
 * no hace falta porque Npcap arrastra winsock2.h, que ya los define. */
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "data_reader.h"

/* * Formato esperado en cada línea del archivo log:
 * timestamp src_ip src_port dst_ip dst_port protocol size
 * Ejemplo: 1700000000 192.168.1.1 54321 10.0.0.1 22 TCP 64
 */

int data_reader_from_log(const char *filepath, NetworkPacket *out_packets, int max_packets) {
    FILE *f = fopen(filepath, "r");
    if (!f) return -1;

    int count = 0;
    char line[256];
    while (count < max_packets && fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        NetworkPacket *p = &out_packets[count];
        long ts;
        if (sscanf(line, "%ld %45s %d %45s %d %7s %d",
                   &ts,
                   p->src_ip, &p->src_port,
                   p->dst_ip, &p->dst_port,
                   p->protocol, &p->size) == 7) {
            p->timestamp = (time_t)ts;
            count++;
        }
    }
    fclose(f);
    return count;
}

/* ---------------------------------------------------------------- */
/* Captura en vivo: usa Npcap/libpcap si el binario se compiló con  */
/* -DHAVE_PCAP. Si no, usa un simulador interno con datos de prueba.*/
/* ---------------------------------------------------------------- */

static volatile int g_stop_capture = 0;

#ifdef HAVE_PCAP
#include <pcap.h>
#ifndef _WIN32
#include <arpa/inet.h>   /* inet_ntoa en Linux/macOS (en Windows ya llega via winsock2.h) */
#endif

/*
 * Structs propias de cabecera IPv4/TCP/UDP, en vez de usar netinet/ip.h,
 * netinet/tcp.h y netinet/udp.h: esos headers son de Linux/BSD y NO
 * existen en Windows/MinGW, lo que rompía la compilación con Npcap.
 * Definiendo estas structs "a mano" el parseo funciona igual en ambos
 * sistemas operativos.
 */
#pragma pack(push, 1)
typedef struct {
    unsigned char  ver_ihl;      /* version (4 bits) + IHL en palabras de 32 bits (4 bits) */
    unsigned char  tos;
    unsigned short total_length;
    unsigned short id;
    unsigned short flags_fo;
    unsigned char  ttl;
    unsigned char  protocol;     /* 6 = TCP, 17 = UDP */
    unsigned short checksum;
    unsigned int   src_addr;
    unsigned int   dst_addr;
} dr_ip_header;

typedef struct {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int   seq;
    unsigned int   ack;
    unsigned char  data_offset;  /* 4 bits alto = longitud de cabecera en palabras de 32 bits */
    unsigned char  flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
} dr_tcp_header;

typedef struct {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned short checksum;
} dr_udp_header;
#pragma pack(pop)

#define DR_IPPROTO_TCP 6
#define DR_IPPROTO_UDP 17

static void (*g_on_packet)(NetworkPacket *) = NULL;
static pcap_t *g_handle = NULL;

int data_reader_has_real_capture(void) { return 1; }

int data_reader_list_devices(char out_names[][DR_DEVICE_NAME_LEN],
                              char out_descs[][DR_DEVICE_DESC_LEN],
                              int max_devices,
                              char *errbuf, size_t errbuf_len) {
    pcap_if_t *alldevs;
    char pcap_err[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, pcap_err) == -1) {
        if (errbuf) snprintf(errbuf, errbuf_len, "pcap_findalldevs: %s", pcap_err);
        return -1;
    }

    int count = 0;
    for (pcap_if_t *d = alldevs; d != NULL && count < max_devices; d = d->next) {
        snprintf(out_names[count], DR_DEVICE_NAME_LEN, "%s", d->name);
        /* Anexamos el estado real (conectada/activa) a la descripción para
         * que sea fácil elegir a mano la interfaz correcta si hiciera falta. */
        int connected = (d->flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_CONNECTED;
        int up        = (d->flags & PCAP_IF_UP) != 0;
        snprintf(out_descs[count], DR_DEVICE_DESC_LEN, "%s%s%s",
                  d->description ? d->description : "(sin descripcion)",
                  connected ? " [conectada]" : (up ? " [activa]" : " [inactiva]"),
                  (d->flags & PCAP_IF_LOOPBACK) ? " [loopback]" : "");
        count++;
    }
    pcap_freealldevs(alldevs);

    if (count == 0 && errbuf) {
        snprintf(errbuf, errbuf_len,
                 "No se encontraron interfaces. En Windows: instala Npcap "
                 "(https://npcap.com) marcando 'WinPcap API-compatible Mode' "
                 "y corre el programa como Administrador.");
    }
    return count;
}

/* Autoselecciona la interfaz más probable para captura real, usando los
 * flags que reporta Npcap en vez de simplemente tomar la primera de la
 * lista (eso puede terminar eligiendo un adaptador virtual como "WAN
 * Miniport" sin tráfico real, en vez de la WiFi/Ethernet física). Se
 * puntúa cada interfaz y se elige la de mayor puntaje:
 *   +100 si está CONECTADA
 *   + 10 si está activa (UP)
 *   +  5 si está RUNNING
 *   -1000 si es loopback (se descarta en la práctica) */
/* Adaptadores virtuales conocidos que suelen reportarse como "conectados"
 * en Windows pero NUNCA tienen trafico real de usuario: VPN/RAS interno
 * (WAN Miniport), maquinas virtuales (VMware/VirtualBox) y el adaptador
 * de Wi-Fi Direct. Se descartan de la auto-seleccion aunque su flag de
 * conexion este activo, para no elegir "WAN Miniport (IPv6)" en vez de
 * la tarjeta Wi-Fi/Ethernet real del usuario. */
static int is_virtual_adapter(const char *description) {
    if (!description) return 0;
    static const char *blacklist[] = {
        "WAN Miniport",
        "Virtual Ethernet Adapter",   /* VMware */
        "VirtualBox",
        "Wi-Fi Direct Virtual Adapter",
        "Bluetooth",
        NULL
    };
    for (int i = 0; blacklist[i]; i++) {
        if (strstr(description, blacklist[i])) return 1;
    }
    return 0;
}

static int autoselect_device(char *out_name, size_t out_len, char *errbuf, size_t errbuf_len) {
    pcap_if_t *alldevs;
    char pcap_err[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, pcap_err) == -1) {
        snprintf(errbuf, errbuf_len, "pcap_findalldevs: %s", pcap_err);
        return -1;
    }
    if (!alldevs) {
        snprintf(errbuf, errbuf_len,
                 "No hay interfaces de red disponibles para Npcap/libpcap. "
                 "Verifica que Npcap este instalado y que el programa corra "
                 "como Administrador.");
        return -1;
    }

    pcap_if_t *best = NULL;
    int best_score = -1;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        if (d->flags & PCAP_IF_LOOPBACK) continue;
        if (is_virtual_adapter(d->description)) continue;
        int score = 0;
        if ((d->flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_CONNECTED) score += 100;
        if (d->flags & PCAP_IF_UP)      score += 10;
        if (d->flags & PCAP_IF_RUNNING) score += 5;
        if (score > best_score) { best_score = score; best = d; }
    }
    /* Si TODO lo real quedo descartado (caso raro), preferimos igual una
     * interfaz no-loopback aunque sea virtual, antes que fallar del todo. */
    if (!best) {
        for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
            if (d->flags & PCAP_IF_LOOPBACK) continue;
            best = d;
            break;
        }
    }
    if (!best) best = alldevs; /* si todo lo demas falla, usa la primera igual */

    snprintf(out_name, out_len, "%s", best->name);
    pcap_freealldevs(alldevs);
    return 0;
}

static void pcap_callback(u_char *args, const struct pcap_pkthdr *header,
                          const u_char *packet) {
    (void)args;

    /* Salta la cabecera Ethernet (14 bytes) para leer directo la IP */
    if ((size_t)header->caplen < 14 + sizeof(dr_ip_header)) return;
    const dr_ip_header *ip_hdr = (const dr_ip_header *)(packet + 14);

    NetworkPacket np;
    memset(&np, 0, sizeof(np));
    np.timestamp = (time_t)header->ts.tv_sec;
    np.size      = (int)header->len;

    /* Extrae las direcciones IP de origen y destino */
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_hdr->src_addr;
    dst_addr.s_addr = ip_hdr->dst_addr;
    snprintf(np.src_ip, sizeof(np.src_ip), "%s", inet_ntoa(src_addr));
    snprintf(np.dst_ip, sizeof(np.dst_ip), "%s", inet_ntoa(dst_addr));

    int ip_hlen = (ip_hdr->ver_ihl & 0x0F) * 4;
    if (ip_hdr->protocol == DR_IPPROTO_TCP &&
        (size_t)header->caplen >= 14 + (size_t)ip_hlen + sizeof(dr_tcp_header)) {
        strncpy(np.protocol, "TCP", sizeof(np.protocol) - 1);
        const dr_tcp_header *tcp = (const dr_tcp_header *)((const u_char *)ip_hdr + ip_hlen);
        np.src_port = ntohs(tcp->src_port);
        np.dst_port = ntohs(tcp->dst_port);
    } else if (ip_hdr->protocol == DR_IPPROTO_UDP &&
               (size_t)header->caplen >= 14 + (size_t)ip_hlen + sizeof(dr_udp_header)) {
        strncpy(np.protocol, "UDP", sizeof(np.protocol) - 1);
        const dr_udp_header *udp = (const dr_udp_header *)((const u_char *)ip_hdr + ip_hlen);
        np.src_port = ntohs(udp->src_port);
        np.dst_port = ntohs(udp->dst_port);
    } else {
        strncpy(np.protocol, "ICMP", sizeof(np.protocol) - 1);
    }

    if (g_on_packet) g_on_packet(&np);
}

int data_reader_open_capture(const char *device, char *errbuf, size_t errbuf_len,
                              char *out_device_used, size_t out_device_used_len) {
    char pcap_err[PCAP_ERRBUF_SIZE];
    char real_device[DR_DEVICE_NAME_LEN];

    /* Npcap (Windows) NO soporta el pseudo-dispositivo "any" de Linux.
     * Si no viene device, viene vacío, o es "any", autoseleccionamos
     * la primera interfaz real disponible. */
    if (!device || device[0] == '\0' || strcmp(device, "any") == 0) {
        if (autoselect_device(real_device, sizeof(real_device), errbuf, errbuf_len) != 0) {
            return -1;
        }
    } else {
        snprintf(real_device, sizeof(real_device), "%s", device);
    }

    g_handle = pcap_open_live(real_device, 65535, /*promisc=*/1, /*timeout_ms=*/1000, pcap_err);
    if (!g_handle) {
        snprintf(errbuf, errbuf_len,
                 "No se pudo abrir '%s': %s. En Windows revisa que Npcap este "
                 "instalado y ejecuta el programa como Administrador.",
                 real_device, pcap_err);
        return -1;
    }

    if (out_device_used) snprintf(out_device_used, out_device_used_len, "%s", real_device);
    return 0;
}

void data_reader_run_capture(void (*on_packet)(NetworkPacket *)) {
    if (!g_handle) return; /* hay que llamar data_reader_open_capture() antes */
    g_on_packet    = on_packet;
    g_stop_capture = 0;
    pcap_loop(g_handle, -1, pcap_callback, NULL);
    if (g_handle) {
        pcap_close(g_handle);
        g_handle = NULL;
    }
}

void data_reader_stop_capture(void) {
    if (g_handle) pcap_breakloop(g_handle);
    g_stop_capture = 1;
}

#else /* !HAVE_PCAP: modo simulación */

/* * Modo simulación (cuando no se compiló con -DHAVE_PCAP).
 * Genera tráfico de red falso para poder probar la API y el detector sin
 * necesitar Npcap/libpcap instalados. NO es captura real.
 */

#ifdef _WIN32
  #include <windows.h>
  #define usleep(us) Sleep((us)/1000)
#else
  #include <unistd.h>
#endif

static void (*g_on_packet_sim)(NetworkPacket *) = NULL;

static const char *SAMPLE_IPS[]   = {"10.0.0.1","10.0.0.2","192.168.1.50","172.16.0.3"};
static const char *SAMPLE_PROTOS[] = {"TCP","UDP","TCP","TCP"};
static const int   SAMPLE_DPORTS[] = {22, 80, 443, 8080, 22, 22, 3306, 22};

int data_reader_has_real_capture(void) { return 0; }

int data_reader_list_devices(char out_names[][DR_DEVICE_NAME_LEN],
                              char out_descs[][DR_DEVICE_DESC_LEN],
                              int max_devices,
                              char *errbuf, size_t errbuf_len) {
    (void)max_devices;
    if (errbuf) {
        snprintf(errbuf, errbuf_len,
                 "Binario compilado sin -DHAVE_PCAP: no hay interfaces reales, "
                 "solo el simulador interno. Recompila con -DHAVE_PCAP y "
                 "enlazando Npcap/libpcap para ver interfaces reales.");
    }
    if (max_devices > 0) {
        snprintf(out_names[0], DR_DEVICE_NAME_LEN, "sim0");
        snprintf(out_descs[0], DR_DEVICE_DESC_LEN, "Interfaz simulada (sin captura real)");
        return 1;
    }
    return 0;
}

int data_reader_open_capture(const char *device, char *errbuf, size_t errbuf_len,
                              char *out_device_used, size_t out_device_used_len) {
    (void)device;
    (void)errbuf; (void)errbuf_len;
    if (out_device_used) snprintf(out_device_used, out_device_used_len, "sim0");
    return 0; /* el simulador siempre "abre" correctamente */
}

void data_reader_run_capture(void (*on_packet)(NetworkPacket *)) {
    g_on_packet_sim = on_packet;
    g_stop_capture  = 0;
    srand((unsigned)time(NULL));
    int i = 0;
    while (!g_stop_capture) {
        NetworkPacket np;
        memset(&np, 0, sizeof(np));
        np.timestamp = time(NULL);
        int src_idx = rand() % 4;
        strncpy(np.src_ip,   SAMPLE_IPS[src_idx],   sizeof(np.src_ip)   - 1);
        strncpy(np.dst_ip,   "192.168.1.1",          sizeof(np.dst_ip)   - 1);
        strncpy(np.protocol, SAMPLE_PROTOS[src_idx], sizeof(np.protocol) - 1);
        np.src_port = 1024 + rand() % 60000;
        np.dst_port = SAMPLE_DPORTS[i % 8];
        np.size     = 40 + rand() % 1460;

        if (g_on_packet_sim) g_on_packet_sim(&np);
        i++;

        /* Pausa para simular un tráfico de 5 paquetes por segundo */
        usleep(200000);
    }
}

void data_reader_stop_capture(void) {
    g_stop_capture = 1;
}
#endif
