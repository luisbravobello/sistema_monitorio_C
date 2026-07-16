#ifndef MODELS_H
#define MODELS_H

#include <time.h>

/*
 * Estructuras centrales compartidas en todo el backend C.
 * Importante: Si modificas estos campos, actualiza docs/Documentacion.md (sección 3.4) y UI/models.py para no romper el formato JSON.
 */

#define IP_STR_LEN      46   /* Capacidad para IPv4 e IPv6 */
#define PROTO_STR_LEN   8    /* TCP, UDP, ICMP */
#define THREAT_TYPE_LEN 32   /* PORT_SCAN, SSH_BRUTE */

/*
  Representa un paquete de red interceptado en vivo o leído de un log.
 */
typedef struct {
    char   src_ip[IP_STR_LEN];
    char   dst_ip[IP_STR_LEN];
    int    src_port;
    int    dst_port;
    char   protocol[PROTO_STR_LEN];
    int    size;        /* Tamaño total en bytes */
    time_t timestamp;
} NetworkPacket;

/*
  Alerta generada cuando el detector encuentra una anomalía en un paquete.
 */
typedef struct {
    NetworkPacket packet;
    char          threat_type[THREAT_TYPE_LEN]; /* Tipo de ataque */
    int           severity;   /* Escala del 1 (Bajo) al 5 (Crítico) */
    int           confirmed;  /* 0 = Sospecha, 1 = Confirmado */
} ThreatEvent;

#endif /* MODELS_H */