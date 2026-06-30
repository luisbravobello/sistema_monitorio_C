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
/* Captura en vivo: usa la librería pcap si está instalada.         */
/* Si no la encuentra, usa un simulador interno con datos de prueba.*/
/* ---------------------------------------------------------------- */

static volatile int g_stop_capture = 0;

#ifdef HAVE_PCAP
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static void (*g_on_packet)(NetworkPacket *) = NULL;
static pcap_t *g_handle = NULL;

static void pcap_callback(u_char *args, const struct pcap_pkthdr *header,
                          const u_char *packet) {
    (void)args;
    
    /* Salta la cabecera Ethernet (14 bytes) para leer directo la IP */
    const struct ip *ip_hdr = (const struct ip *)(packet + 14);
    if ((size_t)header->caplen < 14 + sizeof(struct ip)) return;

    NetworkPacket np;
    memset(&np, 0, sizeof(np));
    np.timestamp = (time_t)header->ts.tv_sec;
    np.size      = (int)header->len;

    /* Extrae las direcciones IP de origen y destino */
    snprintf(np.src_ip, sizeof(np.src_ip), "%s", inet_ntoa(ip_hdr->ip_src));
    snprintf(np.dst_ip, sizeof(np.dst_ip), "%s", inet_ntoa(ip_hdr->ip_dst));

    int ip_hlen = ip_hdr->ip_hl * 4;
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        strncpy(np.protocol, "TCP", sizeof(np.protocol));
        const struct tcphdr *tcp = (const struct tcphdr *)((u_char *)ip_hdr + ip_hlen);
        np.src_port = ntohs(tcp->th_sport);
        np.dst_port = ntohs(tcp->th_dport);
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        strncpy(np.protocol, "UDP", sizeof(np.protocol));
        const struct udphdr *udp = (const struct udphdr *)((u_char *)ip_hdr + ip_hlen);
        np.src_port = ntohs(udp->uh_sport);
        np.dst_port = ntohs(udp->uh_dport);
    } else {
        strncpy(np.protocol, "ICMP", sizeof(np.protocol));
    }

    if (g_on_packet) g_on_packet(&np);
}

int data_reader_start_capture(const char *device, void (*on_packet)(NetworkPacket *)) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
    if (!g_handle) { fprintf(stderr, "pcap: %s\n", errbuf); return -1; }
    g_on_packet   = on_packet;
    g_stop_capture = 0;
    pcap_loop(g_handle, -1, pcap_callback, NULL);
    pcap_close(g_handle);
    g_handle = NULL;
    return 0;
}

void data_reader_stop_capture(void) {
    if (g_handle) pcap_breakloop(g_handle);
    g_stop_capture = 1;
}

#else

/* * Modo simulación (cuando no hay libpcap).
 * Genera tráfico de red falso para poder probar la API y el detector sin hardware real.
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

int data_reader_start_capture(const char *device, void (*on_packet)(NetworkPacket *)) {
    (void)device;
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
    return 0;
}

void data_reader_stop_capture(void) {
    g_stop_capture = 1;
}
#endif