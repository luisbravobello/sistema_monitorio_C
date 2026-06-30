#include <string.h>
#include "search.h"

int search_linear_by_ip(ThreatEvent *events, int n, const char *ip) {
    for (int i = 0; i < n; i++) {
        if (strcmp(events[i].packet.src_ip, ip) == 0) {
            return i;
        }
    }
    return -1;
}

int search_binary_by_timestamp(ThreatEvent *events, int n, time_t timestamp) {
    // PRECONDICIÓN: events debe estar ordenado por timestamp (sort_by_timestamp).
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        time_t mid_ts = events[mid].packet.timestamp;
        if (mid_ts == timestamp) return mid;
        if (mid_ts < timestamp) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;
}