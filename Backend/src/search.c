#include <string.h>
#include "search.h"
#include <time.h>
#include "models.h"
/*
 * Busca un evento por su dirección IP de origen.
 */
int search_linear_by_ip(ThreatEvent *events, int n, const char *ip) {
    // Recorre el arreglo elemento por elemento 
    for (int i = 0; i < n; i++) {
        /* Si encuentra una coincidencia exacta, devuelve la posición actual */
        if (strcmp(events[i].packet.src_ip, ip) == 0) {
            return i;
        }
    }
    /* Retorna -1 si revisó todo el arreglo y no encontró la IP */
    return -1;
}


// Busca un evento rápidamente utilizando su marca de tiempo con timestamp.
 
int search_binary_by_timestamp(ThreatEvent *events, int n, time_t timestamp) {
    /* Requisito obligatorio: El arreglo debe estar ordenado previamente por tiempo */
    int lo = 0, hi = n - 1;
    
    /* Divide el espacio de búsqueda a la mitad en cada iteración */
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        time_t mid_ts = events[mid].packet.timestamp;
        
        /* Si el tiempo coincide, devuelve la posición de inmediato */
        if (mid_ts == timestamp) return mid;
        
        /* Ajusta los límites izquierdo o derecho según corresponda */
        if (mid_ts < timestamp) lo = mid + 1;
        else hi = mid - 1;
    }
    /* Retorna -1 si el timestamp no existe en el registro */
    return -1;
}