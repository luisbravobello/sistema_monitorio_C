#include "sort.h"


// Ordena el arreglo por fecha y hora utilizando el algoritmo de inserción.
 
void sort_by_timestamp(ThreatEvent *events, int n) {
    // Recorre el arreglo empezando desde el segundo elemento 
    for (int i = 1; i < n; i++) {
        ThreatEvent key = events[i];
        int j = i - 1;
        
        // Desplaza hacia la derecha los eventos más recientes para hacer espacio *
        while (j >= 0 && events[j].packet.timestamp > key.packet.timestamp) {
            events[j + 1] = events[j];
            j--;
        }
        // Inserta el evento en su posición correcta (del más antiguo al más nuevo) 
        events[j + 1] = key;
    }
}

/*
 * Ordena pero seria por el nivel de peligro segun la ip
 */
void sort_by_severity(ThreatEvent *events, int n) {
    for (int i = 1; i < n; i++) {
        ThreatEvent key = events[i];
        int j = i - 1;
        
        // Desplaza hacia la derecha los eventos menos graves para hacer espacio 
        while (j >= 0 && events[j].severity < key.severity) {
            events[j + 1] = events[j];
            j--;
        }
        // Inserta el evento dejando las amenazas más críticas al principio 
        events[j + 1] = key;
    }
}