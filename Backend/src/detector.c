#include <string.h>
#include <time.h>
#include "detector.h"

/*
 * Detector simple con ventana de tiempo.
 * Mantiene un historial reducido en memoria estática para detectar
 * PORT_SCAN (muchos dst_port distintos desde mismo src_ip) y
 * SSH_BRUTE (muchos paquetes a puerto 22 desde mismo src_ip).
 */

#define HISTORY_SIZE 256
#define WINDOW_SECS  10
#define PORTSCAN_THRESHOLD  5   /* puertos distintos en la ventana */
#define SSHBRUTE_THRESHOLD  4   /* conexiones a :22 en la ventana  */

typedef struct {
    char   src_ip[46];
    int    dst_port;
    time_t ts;
} HistEntry;

static HistEntry g_history[HISTORY_SIZE];
static int       g_hist_pos = 0;

int detector_analyze(const NetworkPacket *packet, ThreatEvent *out_event) {
    time_t now = packet->timestamp;

    /* Guardar en historial circular */
    g_history[g_hist_pos % HISTORY_SIZE].ts       = now;
    g_history[g_hist_pos % HISTORY_SIZE].dst_port = packet->dst_port;
    strncpy(g_history[g_hist_pos % HISTORY_SIZE].src_ip, packet->src_ip, 45);
    g_hist_pos++;

    int ssh_count  = 0;
    int port_set[1024]; int nports = 0;

    for (int i = 0; i < HISTORY_SIZE; i++) {
        HistEntry *h = &g_history[i];
        if (h->ts == 0) continue;
        if (now - h->ts > WINDOW_SECS) continue;
        if (strcmp(h->src_ip, packet->src_ip) != 0) continue;

        /* SSH brute */
        if (h->dst_port == 22) ssh_count++;

        /* Port scan: contar puertos distintos */
        int found = 0;
        for (int p = 0; p < nports; p++)
            if (port_set[p] == h->dst_port) { found = 1; break; }
        if (!found && nports < 1024) port_set[nports++] = h->dst_port;
    }

    if (ssh_count >= SSHBRUTE_THRESHOLD) {
        out_event->packet = *packet;
        strncpy(out_event->threat_type, "SSH_BRUTE", sizeof(out_event->threat_type) - 1);
        out_event->severity  = 4;
        out_event->confirmed = 1;
        return 1;
    }
    if (nports >= PORTSCAN_THRESHOLD) {
        out_event->packet = *packet;
        strncpy(out_event->threat_type, "PORT_SCAN", sizeof(out_event->threat_type) - 1);
        out_event->severity  = 3;
        out_event->confirmed = 0;
        return 1;
    }
    return 0;
}
