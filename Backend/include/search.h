#ifndef SEARCH_H
#define SEARCH_H

#include <time.h>
#include "models.h"

/*
 * Busca secuencialmente un evento según su IP de origen.
 * Retorna la posición en el arreglo, o -1 si no lo encuentra.
 */
int search_linear_by_ip(ThreatEvent *events, int n, const char *ip);

/*
 Busca rápidamente un evento exacto por su marca de tiempo
 Importante: El arreglo debe estar previamente ordenado con sort_by_timestamp().
 Retorna la posición en el arreglo, o -1 si no lo encuentra.
 */
int search_binary_by_timestamp(ThreatEvent *events, int n, time_t timestamp);

#endif /* SEARCH_H */