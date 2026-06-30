#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "viewmodel.h"
#include "sort.h"

#define EVENT_JSON_SIZE 256
#define HEADER_SIZE     32


 //Función interna que calcula la memoria necesaria y construye el texto JSON
// concatenando los datos de cada evento del arreglo.
 
static char *events_to_json_internal(ThreatEvent *events, int n) {
    if (n == 0) {
        char *out = malloc(3);
        strcpy(out, "[]");
        return out;
    }
    size_t cap = (size_t)n * EVENT_JSON_SIZE + HEADER_SIZE;
    char *out = malloc(cap);
    if (!out) return NULL;
    int pos = 0;
    pos += snprintf(out + pos, cap - pos, "[");
    for (int i = 0; i < n; i++) {
        ThreatEvent *e = &events[i];
        pos += snprintf(out + pos, cap - pos,
            "%s{\"ip\":\"%s\",\"puerto\":%d,\"tipo\":\"%s\",\"severidad\":%d,\"timestamp\":%ld}",
            i ? "," : "",
            e->packet.src_ip, e->packet.dst_port,
            e->threat_type, e->severity,
            (long)e->packet.timestamp);
    }
    pos += snprintf(out + pos, cap - pos, "]");
    return out;
}


//Convierte y devuelve la lista completa de eventos a formato JSON sin aplicar filtros.
 
char *viewmodel_events_to_json(ThreatEvent *events, int n) {
    return events_to_json_internal(events, n);
}


//Genera el JSON exclusivamente de las amenazas confirmadas y ordenadas por nivel de riesgo.
//Trabaja sobre una copia temporal para no desordenar el arreglo principal de la aplicación.

char *viewmodel_alerts_to_json(ThreatEvent *events, int n) {
    /* Copiar para no mutar el arreglo original */
    ThreatEvent *copy = malloc((size_t)n * sizeof(ThreatEvent));
    if (!copy) { char *o = malloc(3); strcpy(o, "[]"); return o; }
    memcpy(copy, events, (size_t)n * sizeof(ThreatEvent));
    sort_by_severity(copy, n);
    
    /* Filtrar dejando solo las amenazas confirmadas (confirmed == 1) */
    ThreatEvent *filtered = malloc((size_t)n * sizeof(ThreatEvent));
    int fc = 0;
    for (int i = 0; i < n; i++)
        if (copy[i].confirmed) filtered[fc++] = copy[i];
        
    char *out = events_to_json_internal(filtered, fc);
    
    /* Liberar la memoria temporal utilizada */
    free(copy); free(filtered);
    return out;
}


 // Analiza todos los eventos registrados para contar cuántos ataques hay de cada tipo 
 // y cuántos corresponden a cada nivel de severidad, agrupándolos en un JSON de resumen.
 
char *viewmodel_statistics_to_json(ThreatEvent *events, int n) {
    /* Contar por tipo y severidad */
    typedef struct { char tipo[32]; int count; } TipoCount;
    TipoCount tipos[64]; int ntypes = 0;
    int por_sev[6] = {0};  /* índices 1..5 */

    for (int i = 0; i < n; i++) {
        /* Agrupar por tipo de amenaza */
        int found = 0;
        for (int t = 0; t < ntypes; t++) {
            if (strcmp(tipos[t].tipo, events[i].threat_type) == 0) {
                tipos[t].count++; found = 1; break;
            }
        }
        if (!found && ntypes < 64) {
            strncpy(tipos[ntypes].tipo, events[i].threat_type, 31);
            tipos[ntypes].tipo[31] = '\0';
            tipos[ntypes++].count = 1;
        }
        
        /* Agrupar por nivel de severidad */
        int s = events[i].severity;
        if (s >= 1 && s <= 5) por_sev[s]++;
    }

    size_t cap = 512 + (size_t)ntypes * 64;
    char *out = malloc(cap);
    if (!out) return NULL;
    int pos = 0;
    pos += snprintf(out + pos, cap - pos,
        "{\"total_paquetes\":%d,\"amenazas_por_tipo\":{", n);
    for (int t = 0; t < ntypes; t++)
        pos += snprintf(out + pos, cap - pos,
            "%s\"%s\":%d", t ? "," : "", tipos[t].tipo, tipos[t].count);
    pos += snprintf(out + pos, cap - pos, "},\"amenazas_por_severidad\":{");
    int first = 1;
    for (int s = 1; s <= 5; s++) {
        if (por_sev[s]) {
            pos += snprintf(out + pos, cap - pos,
                "%s\"%d\":%d", first ? "" : ",", s, por_sev[s]);
            first = 0;
        }
    }
    pos += snprintf(out + pos, cap - pos, "}}");
    return out;
}