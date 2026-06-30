#include "sort.h"

void sort_by_timestamp(ThreatEvent *events, int n) {
    for (int i = 1; i < n; i++) {
        ThreatEvent key = events[i];
        int j = i - 1;
        while (j >= 0 && events[j].packet.timestamp > key.packet.timestamp) {
            events[j + 1] = events[j];
            j--;
        }
        events[j + 1] = key;
    }
}

void sort_by_severity(ThreatEvent *events, int n) {
    // Mismo algoritmo, orden descendente (más crítico primero).
    for (int i = 1; i < n; i++) {
        ThreatEvent key = events[i];
        int j = i - 1;
        while (j >= 0 && events[j].severity < key.severity) {
            events[j + 1] = events[j];
            j--;
        }
        events[j + 1] = key;
    }
}